# speedflare  
**Measure your internet speed through Cloudflare's global network with a simple CLI tool.**  

## About  
speedflare is a command-line utility inspired by speedtest-go, designed to test your internet connection performance using Cloudflare's extensive server network. It measures latency (with jitter), download, and upload speeds, providing both human-readable and JSON outputs for easy integration with scripts and monitoring tools.  

## Highlights  
- **Cloudflare Integration**: Utilizes Cloudflare's globally distributed servers for accurate speed measurements.  
- **Comprehensive Metrics**:  
  - Latency (average, jitter, min, max)  
  - Download/Upload speeds (Mbps)  
  - Data consumed during tests  
- **Multi-Connection Support**: Test using single or multiple parallel connections (`--workers`).  
- **Protocol Control**: Force IPv4/IPv6-only testing.  
- **JSON Output**: Machine-readable results for automation (`--json`).   

## Installation  

### Prebuilt Binaries  
1. Visit the [Releases page](https://github.com/idanyas/speedflare/releases).  
2. Download the binary for your OS/architecture.  
3. Make it executable and run:  
   ```bash 
   chmod +x speedflare 
   ./speedflare 
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
```  

---  
*Created by [idanya](https://idanya.ru). Report issues or contribute on [GitHub](https://github.com/idanyas/speedflare).*
