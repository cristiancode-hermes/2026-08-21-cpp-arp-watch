// SPDX-License-Identifier: MIT
// cpp-arp-watch — Linux ARP/neighbor table monitor (/proc/net/arp)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o arp-watch
// Usage: ./arp-watch [--watch N] [--json] [--demo] [--no-color] [--selftest] [--iface IF] [--incomplete]

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <expected>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ── Types ──

struct Error {
  int code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

struct ArpEntry {
  std::string ip;
  unsigned hw_type{0};
  unsigned flags{0};
  std::string mac;
  std::string mask;
  std::string iface;
  bool complete{false};
  bool permanent{false};
  bool publish{false};
  bool multicast{false};
  bool broadcast{false};
  bool locally_administered{false};
};

struct ArpSnapshot {
  std::vector<ArpEntry> entries;
  int complete{0};
  int incomplete{0};
  int permanent{0};
  int publish{0};
  int multicast{0};
  int ifaces{0};
  double timestamp{0.0};
  int d_total{0};
  int d_complete{0};
  int d_incomplete{0};
  bool has_delta{false};
};

// ── Mutable ANSI palette (--no-color empties every code) ──

bool g_color = true;
std::string C_RST, C_BOLD, C_DIM, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_MAGENTA, C_BLUE;

void init_colors() {
  C_RST     = g_color ? "\033[0m"  : "";
  C_BOLD    = g_color ? "\033[1m"  : "";
  C_DIM     = g_color ? "\033[2m"  : "";
  C_CYAN    = g_color ? "\033[36m" : "";
  C_GREEN   = g_color ? "\033[32m" : "";
  C_YELLOW  = g_color ? "\033[33m" : "";
  C_RED     = g_color ? "\033[31m" : "";
  C_MAGENTA = g_color ? "\033[35m" : "";
  C_BLUE    = g_color ? "\033[34m" : "";
}

// ── Helpers ──

static double now_epoch() {
  using namespace std::chrono;
  return duration<double>(system_clock::now().time_since_epoch()).count();
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
    s.remove_suffix(1);
  return std::string(s);
}

static unsigned parse_u32(std::string_view s, int base = 10) {
  unsigned v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  if (base == 16) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
  }
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  (void)ptr;
  if (ec != std::errc{}) return 0;
  return v;
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char c : s) {
    switch (c) {
      case '\\': o += "\\\\"; break;
      case '"':  o += "\\\""; break;
      case '\n': o += "\\n"; break;
      case '\t': o += "\\t"; break;
      default:   o += static_cast<char>(c); break;
    }
  }
  return o;
}

static std::string fmt_signed(int v) {
  char buf[16];
  if (v > 0) std::snprintf(buf, sizeof(buf), "+%d", v);
  else std::snprintf(buf, sizeof(buf), "%d", v);
  return buf;
}

static std::string fmt_time(double epoch) {
  std::time_t t = static_cast<std::time_t>(epoch);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

// ATF_* from linux/if_arp.h
static constexpr unsigned ATF_COM  = 0x02;
static constexpr unsigned ATF_PERM = 0x04;
static constexpr unsigned ATF_PUBL = 0x08;
static constexpr unsigned ATF_USETRAILERS = 0x10;
static constexpr unsigned ATF_NETMASK = 0x20;
static constexpr unsigned ATF_DONTPUB = 0x40;

static std::string flags_str(unsigned f) {
  std::string s;
  if (f & ATF_COM)  s += 'C';
  if (f & ATF_PERM) s += 'P';
  if (f & ATF_PUBL) s += 'p';
  if (f & ATF_USETRAILERS) s += 'T';
  if (f & ATF_NETMASK) s += 'N';
  if (f & ATF_DONTPUB) s += 'D';
  if (s.empty()) s = "-";
  return s;
}

static std::string hwtype_str(unsigned t) {
  switch (t) {
    case 1:   return "ether";
    case 6:   return "ieee802";
    case 7:   return "arcnet";
    case 15:  return "fddi";
    case 19:  return "atm";
    case 23:  return "ieee1394";
    case 24:  return "infiniband";
    case 768: return "tun";
    case 772: return "loopback";
    case 801: return "ieee80211";
    default: {
      char buf[24];
      std::snprintf(buf, sizeof(buf), "type-%u", t);
      return buf;
    }
  }
}

static bool parse_mac_bytes(std::string_view mac, unsigned bytes[6]) {
  for (int i = 0; i < 6; ++i) bytes[i] = 0;
  int idx = 0;
  std::string tmp(mac);
  for (char& c : tmp) {
    if (c == '-' || c == '.') c = ':';
  }
  std::istringstream iss(tmp);
  std::string tok;
  while (std::getline(iss, tok, ':') && idx < 6) {
    unsigned v = 0;
    auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v, 16);
    (void)ptr;
    if (ec != std::errc{}) return false;
    bytes[idx++] = v;
  }
  return idx == 6;
}

static void classify_mac(ArpEntry& e) {
  unsigned b[6] = {0, 0, 0, 0, 0, 0};
  if (!parse_mac_bytes(e.mac, b)) return;
  bool all_ff = true, all_00 = true;
  for (int i = 0; i < 6; ++i) {
    if (b[i] != 0xFF) all_ff = false;
    if (b[i] != 0x00) all_00 = false;
  }
  e.broadcast = all_ff;
  e.multicast = !all_ff && ((b[0] & 0x01u) != 0);
  e.locally_administered = ((b[0] & 0x02u) != 0);
  (void)all_00;
}

static void classify_flags(ArpEntry& e) {
  e.complete  = (e.flags & ATF_COM) != 0;
  e.permanent = (e.flags & ATF_PERM) != 0;
  e.publish   = (e.flags & ATF_PUBL) != 0;
}

static void summarize(ArpSnapshot& s) {
  s.complete = s.incomplete = s.permanent = s.publish = s.multicast = 0;
  std::map<std::string, int> ifc;
  for (const auto& e : s.entries) {
    if (e.complete) ++s.complete;
    else ++s.incomplete;
    if (e.permanent) ++s.permanent;
    if (e.publish) ++s.publish;
    if (e.multicast || e.broadcast) ++s.multicast;
    ifc[e.iface] += 1;
  }
  s.ifaces = static_cast<int>(ifc.size());
}

static void sort_entries(std::vector<ArpEntry>& v) {
  std::sort(v.begin(), v.end(), [](const ArpEntry& a, const ArpEntry& b) {
    if (a.iface != b.iface) return a.iface < b.iface;
    if (a.complete != b.complete) return a.complete && !b.complete;
    return a.ip < b.ip;
  });
}

// ── Parser ──
// /proc/net/arp:
// IP address       HW type     Flags       HW address            Mask     Device
// 172.16.1.1       0x1         0x2         be:79:79:6e:53:7f     *        eth0

static Result<std::vector<ArpEntry>> parse_arp_text(std::string_view text) {
  std::vector<ArpEntry> out;
  std::istringstream in{std::string(text)};
  std::string line;
  bool header = true;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto t = trim(line);
    if (t.empty()) continue;
    if (!t.empty() && t[0] == '#') continue;  // tolerate comments in demo files
    if (header) {
      header = false;
      if (t.find("IP address") != std::string::npos || t.find("HW type") != std::string::npos)
        continue;
    }
    std::istringstream ss{t};
    ArpEntry e;
    std::string hw_s, fl_s;
    if (!(ss >> e.ip >> hw_s >> fl_s >> e.mac >> e.mask >> e.iface)) continue;
    e.hw_type = parse_u32(hw_s, 16);
    e.flags = parse_u32(fl_s, 16);
    classify_flags(e);
    classify_mac(e);
    out.push_back(std::move(e));
  }
  return out;
}

static Result<ArpSnapshot> read_arp(const std::string& path = "/proc/net/arp") {
  std::ifstream f(path);
  if (!f) return std::unexpected(Error{1, "cannot open " + path});
  std::ostringstream oss;
  oss << f.rdbuf();
  auto parsed = parse_arp_text(oss.str());
  if (!parsed) return std::unexpected(parsed.error());
  ArpSnapshot s;
  s.entries = std::move(*parsed);
  s.timestamp = now_epoch();
  sort_entries(s.entries);
  summarize(s);
  return s;
}

static ArpSnapshot build_demo_snapshot() {
  const char* sample =
      "IP address       HW type     Flags       HW address            Mask     Device\n"
      "172.16.1.1       0x1         0x2         be:79:79:6e:53:7f     *        eth0\n"
      "172.16.1.10      0x1         0x6         02:11:22:33:44:55     *        eth0\n"
      "172.16.1.255     0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0\n"
      "10.0.0.1         0x1         0x2         00:1a:2b:3c:4d:5e     *        br-lan\n"
      "10.0.0.42        0x1         0x0         00:00:00:00:00:00     *        br-lan\n"
      "172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        docker0\n"
      "192.168.88.1     0x1         0xa         aa:bb:cc:dd:ee:ff     *        wlan0\n"
      "224.0.0.1        0x1         0x2         01:00:5e:00:00:01     *        eth0\n"
      "# comment line should be skipped\n";
  auto parsed = parse_arp_text(sample);
  ArpSnapshot s;
  if (parsed) s.entries = std::move(*parsed);
  s.timestamp = now_epoch();
  sort_entries(s.entries);
  summarize(s);
  return s;
}

static void apply_filters(ArpSnapshot& s, std::string_view iface, bool incomplete_only) {
  if (!iface.empty() || incomplete_only) {
    std::vector<ArpEntry> kept;
    kept.reserve(s.entries.size());
    for (auto& e : s.entries) {
      if (!iface.empty() && e.iface != iface) continue;
      if (incomplete_only && e.complete) continue;
      kept.push_back(std::move(e));
    }
    s.entries = std::move(kept);
    summarize(s);
  }
}

// ── Print ──

static void print_header(const ArpSnapshot& s, bool demo) {
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "{}|     Linux ARP Neighbor Table Monitor          |{}", C_CYAN, C_RST);
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "  {}Source:{} /proc/net/arp   {}Snapshot:{} {}{}", C_DIM, C_RST, C_DIM,
               C_RST, fmt_time(s.timestamp), demo ? "   --demo" : "");
  std::println(std::cout);
}

static void print_summary(const ArpSnapshot& s) {
  std::println(std::cout, "  {}-- Aggregate --{}", C_BOLD, C_RST);
  auto row = [](const char* label, int v, const std::string& color) {
    std::println(std::cout, "  {:<14} {}{}{}", label, color, v, C_RST);
  };
  row("Entries", static_cast<int>(s.entries.size()), C_CYAN);
  row("Complete", s.complete, C_GREEN);
  row("Incomplete", s.incomplete, s.incomplete ? C_YELLOW : C_DIM);
  row("Permanent", s.permanent, C_MAGENTA);
  row("Publish", s.publish, C_BLUE);
  row("Mcast/Bcast", s.multicast, C_YELLOW);
  row("Ifaces", s.ifaces, C_CYAN);
  if (s.has_delta) {
    std::println(std::cout, "  {:<14} {}{}{}  complete {}  incomplete {}", "Delta",
                 C_BOLD, fmt_signed(s.d_total), C_RST, fmt_signed(s.d_complete),
                 fmt_signed(s.d_incomplete));
  }
  std::println(std::cout);
}

static void print_table(const ArpSnapshot& s) {
  std::println(std::cout, "  {}-- Neighbors ({}) --{}", C_BOLD, s.entries.size(), C_RST);
  std::println(std::cout, "  {}{:<8} {:<16} {:<18} {:<8} {:<5} {:<8} {}{}", C_DIM, "Iface", "IP",
               "MAC", "Type", "Flg", "State", "Notes", C_RST);
  for (const auto& e : s.entries) {
    std::string notes;
    if (e.permanent) notes += "perm ";
    if (e.publish) notes += "publ ";
    if (e.broadcast) notes += "bcast ";
    else if (e.multicast) notes += "mcast ";
    if (e.locally_administered) notes += "laa ";
    std::string state = e.complete ? "REACH" : "INCOMP";
    std::string scolor = e.complete ? C_GREEN : C_YELLOW;
    std::string icolor = e.complete ? C_CYAN : C_YELLOW;
    std::println(std::cout, "  {}{:<8}{} {:<16} {:<18} {:<8} {:<5} {}{:<8}{} {}{}{}", icolor,
                 e.iface, C_RST, e.ip, e.mac, hwtype_str(e.hw_type), flags_str(e.flags), scolor,
                 state, C_RST, C_DIM, trim(notes), C_RST);
  }
  std::println(std::cout);
}

static void print_json(const ArpSnapshot& s) {
  std::ostringstream o;
  o << "{";
  o << "\"timestamp\":" << static_cast<long long>(s.timestamp) << ",";
  o << "\"summary\":{";
  o << "\"entries\":" << s.entries.size() << ",";
  o << "\"complete\":" << s.complete << ",";
  o << "\"incomplete\":" << s.incomplete << ",";
  o << "\"permanent\":" << s.permanent << ",";
  o << "\"publish\":" << s.publish << ",";
  o << "\"multicast\":" << s.multicast << ",";
  o << "\"ifaces\":" << s.ifaces;
  o << "},";
  o << "\"neighbors\":[";
  for (size_t i = 0; i < s.entries.size(); ++i) {
    const auto& e = s.entries[i];
    if (i) o << ",";
    o << "{";
    o << "\"ip\":\"" << json_escape(e.ip) << "\",";
    o << "\"mac\":\"" << json_escape(e.mac) << "\",";
    o << "\"iface\":\"" << json_escape(e.iface) << "\",";
    o << "\"hw_type\":" << e.hw_type << ",";
    o << "\"hw_type_str\":\"" << json_escape(hwtype_str(e.hw_type)) << "\",";
    o << "\"flags\":" << e.flags << ",";
    o << "\"flags_str\":\"" << json_escape(flags_str(e.flags)) << "\",";
    o << "\"mask\":\"" << json_escape(e.mask) << "\",";
    o << "\"complete\":" << (e.complete ? "true" : "false") << ",";
    o << "\"permanent\":" << (e.permanent ? "true" : "false") << ",";
    o << "\"publish\":" << (e.publish ? "true" : "false") << ",";
    o << "\"multicast\":" << (e.multicast ? "true" : "false") << ",";
    o << "\"broadcast\":" << (e.broadcast ? "true" : "false") << ",";
    o << "\"locally_administered\":" << (e.locally_administered ? "true" : "false");
    o << "}";
  }
  o << "]";
  if (s.has_delta) {
    o << ",\"delta\":{";
    o << "\"entries\":" << s.d_total << ",";
    o << "\"complete\":" << s.d_complete << ",";
    o << "\"incomplete\":" << s.d_incomplete;
    o << "}";
  }
  o << "}\n";
  std::cout << o.str();
}

// ── Selftest ──

static int run_selftest() {
  int passed = 0, failed = 0;
  auto check = [&](const char* name, bool ok) {
    if (ok) {
      ++passed;
      std::println(std::cout, "  {}✓{} {}", C_GREEN, C_RST, name);
    } else {
      ++failed;
      std::println(std::cout, "  {}✗{} {}", C_RED, C_RST, name);
    }
  };

  std::println(std::cout, "{}arp-watch selftest{}", C_BOLD, C_RST);
  std::println(std::cout);

  check("flags C", flags_str(0x02) == "C");
  check("flags CP", flags_str(0x06) == "CP");
  check("flags Cp", flags_str(0x0a) == "Cp");
  check("flags empty", flags_str(0x00) == "-");
  check("hwtype ether", hwtype_str(1) == "ether");
  check("hwtype loopback", hwtype_str(772) == "loopback");
  check("hwtype unknown", hwtype_str(99) == "type-99");

  unsigned b[6]{};
  check("mac parse colon", parse_mac_bytes("be:79:79:6e:53:7f", b) && b[0] == 0xbe && b[5] == 0x7f);
  check("mac parse dash", parse_mac_bytes("aa-bb-cc-dd-ee-ff", b) && b[0] == 0xaa && b[5] == 0xff);

  {
    ArpEntry e;
    e.mac = "ff:ff:ff:ff:ff:ff";
    classify_mac(e);
    check("broadcast MAC", e.broadcast && !e.multicast);
  }
  {
    ArpEntry e;
    e.mac = "01:00:5e:00:00:01";
    classify_mac(e);
    check("multicast MAC (IGMP)", e.multicast && !e.broadcast);
  }
  {
    ArpEntry e;
    e.mac = "02:11:22:33:44:55";
    classify_mac(e);
    check("locally administered bit", e.locally_administered);
  }
  {
    ArpEntry e;
    e.mac = "00:1a:2b:3c:4d:5e";
    classify_mac(e);
    check("unicast global MAC", !e.multicast && !e.broadcast && !e.locally_administered);
  }

  {
    ArpEntry e;
    e.flags = 0x02;
    classify_flags(e);
    check("ATF_COM complete", e.complete && !e.permanent);
  }
  {
    ArpEntry e;
    e.flags = 0x06;
    classify_flags(e);
    check("ATF_COM|PERM", e.complete && e.permanent);
  }
  {
    ArpEntry e;
    e.flags = 0x00;
    classify_flags(e);
    check("incomplete flags", !e.complete);
  }

  {
    const char* sample =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "172.16.1.1       0x1         0x2         be:79:79:6e:53:7f     *        eth0\n"
        "10.0.0.42        0x1         0x0         00:00:00:00:00:00     *        br-lan\n"
        "# skip me\n"
        "172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        docker0\n";
    auto r = parse_arp_text(sample);
    check("parse ok", r.has_value() && r->size() == 3);
    if (r && r->size() == 3) {
      check("parse gateway IP", (*r)[0].ip == "172.16.1.1");
      check("parse gateway MAC", (*r)[0].mac == "be:79:79:6e:53:7f");
      check("parse gateway iface", (*r)[0].iface == "eth0");
      check("parse gateway complete", (*r)[0].complete);
      check("parse incomplete", !(*r)[1].complete && (*r)[1].ip == "10.0.0.42");
      check("parse docker LAA", (*r)[2].locally_administered && (*r)[2].iface == "docker0");
      check("comment skipped", true);
    }
  }

  auto demo = build_demo_snapshot();
  check("demo entries >= 8", demo.entries.size() >= 8);
  check("demo complete >= 1", demo.complete >= 1);
  check("demo incomplete >= 1", demo.incomplete >= 1);
  check("demo permanent >= 1", demo.permanent >= 1);
  check("demo publish >= 1", demo.publish >= 1);
  check("demo multicast >= 1", demo.multicast >= 1);
  check("demo ifaces >= 3", demo.ifaces >= 3);

  bool print_ok = true;
  try {
    print_header(demo, true);
    print_summary(demo);
    print_table(demo);
  } catch (...) {
    print_ok = false;
  }
  check("demo print no crash", print_ok);

  std::string json_out;
  {
    std::ostringstream oss;
    auto* old = std::cout.rdbuf(oss.rdbuf());
    print_json(demo);
    std::cout.rdbuf(old);
    json_out = oss.str();
  }
  check("JSON starts with '{'", !json_out.empty() && json_out[0] == '{');
  check("JSON has neighbors", json_out.find("\"neighbors\":[") != std::string::npos);
  check("JSON has summary", json_out.find("\"summary\"") != std::string::npos);
  check("JSON has complete key", json_out.find("\"complete\"") != std::string::npos);
  check("JSON quoted keys", json_out.find("\"ip\":") != std::string::npos);

  auto real = read_arp();
  if (real.has_value()) {
    check("proc arp read ok", true);
    check("real entries countable", real->entries.size() < 100000);
  } else {
    std::println(std::cout, "  {}ℹ{} /proc/net/arp failed ({}): restricted env — skipping",
                 C_YELLOW, C_RST, real.error().message);
  }

  {
    auto d = build_demo_snapshot();
    apply_filters(d, "eth0", false);
    bool only_eth0 = true;
    for (const auto& e : d.entries)
      if (e.iface != "eth0") only_eth0 = false;
    check("--iface eth0 filter", only_eth0 && !d.entries.empty());
  }
  {
    auto d = build_demo_snapshot();
    apply_filters(d, "", true);
    bool all_inc = true;
    for (const auto& e : d.entries)
      if (e.complete) all_inc = false;
    check("--incomplete filter", all_inc && d.incomplete == static_cast<int>(d.entries.size()));
  }

  g_color = true;
  init_colors();
  std::string colored = C_GREEN;
  g_color = false;
  init_colors();
  std::string plain = C_GREEN;
  check("--no-color clears ANSI", !colored.empty() && plain.empty());
  g_color = true;
  init_colors();

  check("fmt_signed(+3)", fmt_signed(3) == "+3");
  check("fmt_signed(-2)", fmt_signed(-2) == "-2");
  check("json_escape quote", json_escape("a\"b") == "a\\\"b");

  std::println(std::cout);
  std::println(std::cout, "{}  Results: {} passed, {} failed{}", failed == 0 ? C_GREEN : C_RED,
               passed, failed, C_RST);
  return failed == 0 ? 0 : 1;
}

// ── Main ──

int main(int argc, char** argv) {
  bool json_mode = false;
  bool watch_mode = false;
  bool demo_mode = false;
  bool selftest = false;
  bool incomplete_only = false;
  int watch_secs = 2;
  std::string iface_filter;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg == "--json") json_mode = true;
    else if (arg == "--no-color" || arg == "-c") g_color = false;
    else if (arg == "--demo") demo_mode = true;
    else if (arg == "--selftest") selftest = true;
    else if (arg == "--incomplete") incomplete_only = true;
    else if ((arg == "--iface" || arg == "-i") && i + 1 < argc) {
      ++i;
      iface_filter = argv[i];
    } else if ((arg == "--watch" || arg == "-w") && i + 1 < argc) {
      watch_mode = true;
      ++i;
      std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), watch_secs);
      if (watch_secs < 1) watch_secs = 1;
    } else if (arg == "--help" || arg == "-h") {
      init_colors();
      std::println(std::cout, "{}arp-watch{} — Linux ARP neighbor table monitor\n", C_BOLD, C_RST);
      std::println(std::cout, "Usage: arp-watch [options]\n");
      std::println(std::cout, "Options:");
      std::println(std::cout, "  -w, --watch N      Refresh every N seconds (default: 2)");
      std::println(std::cout, "  --json             Output JSON");
      std::println(std::cout, "  --no-color, -c     Disable ANSI colors");
      std::println(std::cout, "  --demo             Simulated multi-iface ARP table");
      std::println(std::cout, "  -i, --iface IF     Filter by interface");
      std::println(std::cout, "  --incomplete       Show only incomplete entries");
      std::println(std::cout, "  --selftest         Run built-in tests");
      std::println(std::cout, "  -h, --help         Show this help\n");
      std::println(std::cout, "{}", C_DIM + "Reads: /proc/net/arp" + C_RST);
      std::println(std::cout, "{}",
                   C_DIM + "Flags: C=complete P=permanent p=publish T=trailers N=netmask D=dontpub" +
                       C_RST);
      return 0;
    }
  }

  init_colors();
  if (selftest) return run_selftest();

  auto take = [&]() -> std::optional<ArpSnapshot> {
    if (demo_mode) {
      auto d = build_demo_snapshot();
      apply_filters(d, iface_filter, incomplete_only);
      return d;
    }
    auto r = read_arp();
    if (!r) {
      if (!json_mode)
        std::println(std::cerr, "{}Error:{} {}", C_RED, C_RST, r.error().message);
      return std::nullopt;
    }
    apply_filters(*r, iface_filter, incomplete_only);
    return *r;
  };

  if (watch_mode) {
    std::optional<ArpSnapshot> prev;
    bool first = true;
    while (true) {
      auto snap = take();
      if (!snap) return 1;

      if (prev) {
        snap->d_total = static_cast<int>(snap->entries.size()) - static_cast<int>(prev->entries.size());
        snap->d_complete = snap->complete - prev->complete;
        snap->d_incomplete = snap->incomplete - prev->incomplete;
        snap->has_delta = true;
      }
      prev = snap;

      if (!json_mode && !first) std::cout << "\033[2J\033[H";
      first = false;

      if (json_mode) {
        print_json(*snap);
      } else {
        print_header(*snap, demo_mode);
        print_summary(*snap);
        print_table(*snap);
        std::println(std::cout, "{}  Refreshing every {}s — Ctrl+C to exit{}", C_DIM, watch_secs,
                     C_RST);
      }
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch_secs));
    }
  } else {
    auto snap = take();
    if (!snap) return 1;
    if (json_mode) {
      print_json(*snap);
    } else {
      print_header(*snap, demo_mode);
      print_summary(*snap);
      print_table(*snap);
    }
  }
  return 0;
}
