# arp-watch

Monitor de la tabla ARP / vecinos de Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/arp` para mostrar IP, MAC, flags ATF_*, tipo de hardware e interfaz,
clasificando entradas complete / incomplete / permanent / publish y MACs multicast,
broadcast o locally-administered.

## Features

- **Parse de `/proc/net/arp`**: IP, HW type, flags hex, MAC, mask, device
- **Flags ATF_***: C (complete), P (permanent), p (publish), T/N/D
- **Clasificación MAC**: unicast, multicast (01:00:5e/…), broadcast, LAA (bit 1)
- **Estados**: REACH (completa) vs INCOMP (00:00:00:00:00:00 / sin ATF_COM)
- **Watch mode**: refresco periódico con deltas de conteo entre snapshots
- **JSON output**: `summary` + array `neighbors` validable
- **Demo mode**: tabla multi-iface (eth0, br-lan, docker0, wlan0)
- **Filtros**: `--iface IF`, `--incomplete`
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 45 checks (parser, flags, MAC, demo, JSON y `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o arp-watch
```

## Usage

```bash
# Snapshot único (tabla real del host)
./arp-watch

# Modo watch (cada 2s)
./arp-watch --watch 2

# Solo una interfaz
./arp-watch --iface eth0

# Solo incompletas (pendientes de resolver)
./arp-watch --incomplete

# JSON
./arp-watch --json

# Demo (tabla sintética multi-iface)
./arp-watch --demo

# Sin colores
./arp-watch --no-color

# Auto-tests
./arp-watch --selftest
```

## Data Source

| Archivo | Campos |
|---------|--------|
| `/proc/net/arp` | IP address, HW type, Flags, HW address, Mask, Device |

### Flags (`linux/if_arp.h`)

| Bit | Nombre | Significado |
|-----|--------|-------------|
| 0x02 | ATF_COM | entrada completa (MAC válida) |
| 0x04 | ATF_PERM | permanente |
| 0x08 | ATF_PUBL | publish / proxy ARP |
| 0x10 | ATF_USETRAILERS | trailers |
| 0x20 | ATF_NETMASK | usa netmask (proxy) |
| 0x40 | ATF_DONTPUB | no responder |

HW type `0x1` = Ethernet. MAC multicast si el bit 0 del primer octeto está a 1;
locally-administered si el bit 1 está a 1.

## Example Output

```
+================================================+
|     Linux ARP Neighbor Table Monitor          |
+================================================+
  Source: /proc/net/arp

  -- Aggregate --
  Entries        8
  Complete       7
  Incomplete     1
  Permanent      1
  Publish        1
  Mcast/Bcast    2
  Ifaces         4

  -- Neighbors (8) --
  Iface    IP               MAC                Type     Flg   State
  br-lan   10.0.0.1         00:1a:2b:3c:4d:5e  ether    C     REACH
  br-lan   10.0.0.42        00:00:00:00:00:00  ether    -     INCOMP
  docker0  172.17.0.2       02:42:ac:11:00:02  ether    C     REACH    laa
  eth0     172.16.1.1       be:79:79:6e:53:7f  ether    C     REACH
  ...
```

## License

MIT
