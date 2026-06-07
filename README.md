# PyPortScanner

```
 /$$$$$$$  /$$     /$$ /$$$$$$$                       /$$      /$$$$$$                                                             
| $$__  $$|  $$   /$$/| $$__  $$                     | $$     /$$__  $$                                                            
| $$  \ $$ \  $$ /$$/ | $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$  | $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
| $$$$$$$/  \  $$$$/  | $$$$$$$//$$__  $$ /$$__  $$|_  $$_/  |  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
| $$____/    \  $$/   | $$____/| $$  \ $$| $$  \__/  | $$     \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
| $$          | $$    | $$     | $$  | $$| $$        | $$ /$$ /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
| $$          | $$    | $$     |  $$$$$$/| $$        |  $$$$/|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
|__/          |__/    |__/      \______/ |__/         \___/   \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
```

A fast, multi-threaded port scanner written in Python. Supports TCP and UDP scanning, banner grabbing, and multiple output formats.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Positional Arguments](#positional-arguments)
  - [Optional Arguments](#optional-arguments)
- [Examples](#examples)
- [Output](#output)
  - [Console](#console-default)
  - [TXT file](#txt-file-portscannertxt)
  - [JSON file](#json-file-portscannerjson)
- [UDP Scan — Status Reference](#udp-scan--status-reference)
- [Architecture](#architecture)
- [Legal Disclaimer](#️-legal-disclaimer)
- [License](#license)

---

## Features

- **TCP & UDP scanning** — run either protocol individually or both simultaneously
- **Multi-threaded** — up to 150 concurrent threads for high-speed scanning
- **Banner grabbing** — automatically captures service banners on open TCP ports
- **Progress bar** — real-time scan progress via `tqdm`
- **Flexible output** — print to console, save as `.txt`, or export as `.json`
- **Configurable** — customize port range, thread count, and socket timeout via CLI flags

---

## Requirements

- Python 3.9+
- [`tqdm`](https://github.com/tqdm/tqdm)

Install dependencies:

```bash
pip install tqdm
```

---

## Installation

```bash
git clone https://github.com/your-username/pyportscanner.git
cd pyportscanner
pip install tqdm
```

---

## Usage

```bash
python portscanner.py <target> [options]
```

### Positional Arguments

| Argument | Description                                   |
|----------|-----------------------------------------------|
| `target` | IP address or hostname to scan (e.g. `192.168.1.1`) |

### Optional Arguments

| Flag              | Default   | Description                                      |
|-------------------|-----------|--------------------------------------------------|
| `-r`, `--range`   | `1-1024`  | Port range in `START-END` format                 |
| `-t`, `--threads` | `150`     | Number of concurrent worker threads              |
| `--timeout`       | `0.5`     | Socket timeout in seconds                        |
| `--scan-type`     | `TCP`     | Scan protocol: `TCP`, `UDP`, or `BOTH`           |
| `--output`        | _(none)_  | Save results to file: `txt` or `json`            |

---

## Examples

**Basic TCP scan (ports 1–1024):**
```bash
python portscanner.py 192.168.1.1
```

**Scan a custom port range:**
```bash
python portscanner.py 192.168.1.1 -r 1-65535
```

**UDP scan with JSON output:**
```bash
python portscanner.py 192.168.1.1 --scan-type UDP --output json
```

**Full scan (TCP + UDP), 200 threads, saved as TXT:**
```bash
python portscanner.py 192.168.1.1 -r 1-65535 --scan-type BOTH -t 200 --output txt
```

**Slower, more accurate scan with higher timeout:**
```bash
python portscanner.py 192.168.1.1 --timeout 2.0 -t 50
```

---

## Output

### Console (default)
```
TCP 22   -> open   - OpenSSH 8.9p1 Ubuntu
TCP 80   -> open
TCP 443  -> open
UDP 53   -> open|filtered
```

### TXT file (`portscanner.txt`)
Same format as console output, written line by line.

### JSON file (`portscanner.json`)
```json
{
  "target": "192.168.1.1",
  "open_ports": [
    {
      "protocol": "TCP",
      "port": 22,
      "status": "open",
      "banner": "OpenSSH 8.9p1 Ubuntu"
    },
    {
      "protocol": "UDP",
      "port": 53,
      "status": "open|filtered",
      "banner": ""
    }
  ]
}
```

---

## UDP Scan — Status Reference

UDP is connectionless, so port status interpretation differs from TCP:

| Status          | Meaning                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `open`          | A response was received from the target port                            |
| `open\|filtered` | No response (port may be open but silently dropping packets)           |
| `closed`        | An ICMP "port unreachable" or OS error was returned                     |

---

## Architecture

```
main()
 ├── Parse CLI arguments
 ├── fill_queue()       → populates a thread-safe Queue with (protocol, port) tuples
 ├── worker() × N       → threads consume the queue, call portscan() or udp_scan()
 │    ├── portscan()    → TCP connect + banner grab
 │    └── udp_scan()    → UDP sendto + recvfrom
 └── Output results     → console / .txt / .json
```

Results are collected in a shared list protected by a `threading.Lock`, then sorted by protocol and port number before output.

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.  
Scanning networks or systems without explicit permission from the owner is **illegal** in most jurisdictions.  
The authors assume no liability for any misuse of this software.  
**Always obtain proper authorization before scanning any target.**

---

## License

This project is licensed under the [MIT License](LICENSE).
