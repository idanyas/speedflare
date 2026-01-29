# speedflare

**Measure your internet speed through Cloudflare's global network with a simple CLI tool.**

## About

speedflare is a command-line utility inspired by speedtest-go, designed to test your internet connection performance using Cloudflare's extensive server network. It measures latency (with jitter), download, and upload speeds, providing both human-readable and JSON outputs for easy integration with scripts and monitoring tools.

## Highlights

- **Cloudflare Integration**: Utilizes Cloudflare's globally distributed servers for accurate speed measurements.
- **Smart Geolocation**: Uses a multi-tiered approach (GeoIP API -> Colo Location -> Country Average) to calculate precise distances to servers.
- **Routing Analysis**: Automatically detects "fragmented" routing where your ISP might be sending you to a distant Cloudflare server.
- **Server Selection**: Scans Cloudflare's **IPv4** ranges to find alternative datacenters and allows interactive selection.
- **Comprehensive Metrics**:
  - Latency (average, jitter, min, max)
  - Download/Upload speeds (Mbps)
  - Data consumed during tests
- **Protocol Control**: Force IPv4/IPv6-only testing.
- **JSON Output**: Machine-readable results for automation (`--json`).

## How It Works

1. **Trace & Geolocation**: The tool connects to Cloudflare to identify your current Point of Presence (PoP) and queries `api.ipapi.is` to get your approximate coordinates for distance calculations.
2. **Discovery (IPv4)**: It probes specific Cloudflare IPv4 Anycast ranges to check if other datacenters are reachable from your network.
3. **Selection**: If multiple datacenters are found (e.g., you are in Russia but routed to Stockholm), the tool presents an interactive list sorted by distance and country preference.
4. **Measurement**: It performs latency tests followed by parallel download and upload streams.

## Installation

### Prebuilt Binaries, Linux snippet

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/arm.*/arm/;s/i.86/i386/')
curl -Lo speedflare "https://github.com/idanyas/speedflare/releases/latest/download/speedflare_linux_${ARCH}"
chmod +x speedflare && sudo mv speedflare /usr/local/bin/
```

### Via Go Install

```bash
go install github.com/idanyas/speedflare@latest
```

### Build from Source

1. Ensure Go 1.20+ is installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/idanyas/speedflare.git
   cd speedflare
   ```
3. Build and install:
   ```bash
   go build -o speedflare ./cmd/speedflare/main.go
   ```

## Usage

```bash
# Basic speed test
./speedflare

# Force IPv6 and use 8 workers
# Note: Server discovery/selection is skipped in IPv6 mode
./speedflare --ipv6 --workers 8

# Single connection + JSON output
./speedflare --single --json

# Custom latency attempts (default: 10)
./speedflare --latency-attempts 15
```

### Command-Line Options

```
  -j, --json              Output results in JSON format.
      --list              List all Cloudflare server locations.
  -4, --ipv4              Use IPv4 only connection.
  -6, --ipv6              Use IPv6 only connection.
  -l, --latency-attempts  Number of latency attempts (default: 10).
  -s, --single            Use a single connection instead of multiple.
  -w, --workers           Number of workers for multithreaded speedtests (default: 6).
      --insecure          Skip TLS certificate verification (UNSAFE).
      --hide-ip           Hide the IP address in output.
```

## Privacy & External Services

- **Speed Test**: Traffic is generated directly between your machine and `speed.cloudflare.com`.
- **Geolocation**: A single GET request is made to `https://api.ipapi.is` to determine your latitude/longitude for distance calculations. No personal data is stored by the tool.

---

_Created by [idanya](https://idanya.ru). Report issues or contribute on [GitHub](https://github.com/idanyas/speedflare)._
