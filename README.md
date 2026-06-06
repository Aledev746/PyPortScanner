# 🔍 PyPortScanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-4ecdc4?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-383880?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-4ade80?style=for-the-badge)

**A fast, multi-threaded TCP port scanner written in Python.**  
Identify open ports on any host using concurrent socket connections.

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Examples](#-examples) · [Roadmap](#-roadmap)

</div>

---

## 📸 Preview

```
$ python scanner.py --target 192.168.1.1 --ports 1-1024 --threads 150

  ____        ____            _   ____
 |  _ \ _   _|  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
 | |_) | | | | |_) / _ \| '__| __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/| |_| |  __/ (_) | |  | |_ ___) | (_| (_| | | | | | | |  __/ |
 |_|    \__, |_|   \___/|_|   \__|____/ \___\__,_|_| |_|_| |_|\___|_|
         |___/

[*] Target   : 192.168.1.1
[*] Range    : 1 - 1024
[*] Threads  : 150
[*] Timeout  : 0.5s
[*] Started  : 2025-05-22 14:32:01
──────────────────────────────────────────
[+] Port  22  is open  →  SSH
[+] Port  80  is open  →  HTTP
[+] Port 443  is open  →  HTTPS
──────────────────────────────────────────
[*] Scan complete in 3.42s
[*] Open ports: [22, 80, 443]
```

---

## ✨ Features

- ⚡ **Multi-threaded** — scansione concorrente con numero di thread configurabile
- 🔒 **TCP Connect Scan** — usa socket standard, nessun privilegio root richiesto
- ⏱️ **Timeout configurabile** — evita attese inutili su porte filtrate
- 🧵 **Thread-safe** — gestione sicura della lista delle porte aperte con `threading.Lock`
- 📋 **Banner grabbing** *(coming soon)* — identifica i servizi in ascolto
- 💾 **Output su file** *(coming soon)* — salva i risultati in `.json` o `.txt`

---

## 📋 Requirements

- Python **3.8** o superiore
- Nessuna dipendenza esterna — usa solo librerie della standard library

```
socket
threading
queue
typing
```

---

## 🚀 Installation

**1. Clona il repository**
```bash
git clone https://github.com/aledev746/PyPortScanner.git
cd PyPortScanner
```

**2. (Opzionale) Crea un virtual environment**
```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

**3. Nessuna dipendenza da installare** — il progetto usa solo la standard library.

---

## 📖 Usage

```bash
python scanner.py
```

Per personalizzare target, range e thread, modifica le costanti in cima al file:

```python
TARGET     = "127.0.0.1"   # Host da scansionare
NUM_THREADS = 150           # Numero di thread concorrenti
TIMEOUT     = 0.5           # Timeout per ogni connessione (secondi)
```

### Parametri consigliati

| Scenario | Threads | Timeout |
|---|---|---|
| Localhost | 200 | 0.3s |
| LAN locale | 150 | 0.5s |
| Host remoto | 50–100 | 1.0s |

---

## 💡 Examples

**Scansione localhost (porte 1–1023):**
```bash
python scanner.py
# Output: tutte le porte aperte su 127.0.0.1
```

**Risultato tipico:**
```
[+] Port  22 is open   →  SSH
[+] Port  80 is open   →  HTTP
[+] Port 443 is open   →  HTTPS

[*] Scan complete. Open ports: [22, 80, 443]
```

---

## 🏗️ How It Works

```
┌─────────────────────────────────────────────────┐
│                  MAIN THREAD                    │
│                                                 │
│  1. fill_queue()  →  aggiunge porte alla Queue  │
│  2. Avvia N thread worker                       │
│  3. Attende il completamento (join)             │
│  4. Stampa risultati finali                     │
└────────────────────┬────────────────────────────┘
                     │
          ┌──────────▼──────────┐
          │   QUEUE (thread-safe)│
          │  [1, 2, 3, ..., 1023]│
          └──────────┬──────────┘
                     │  get()
        ┌────────────▼─────────────┐
        │      WORKER THREADS      │
        │                          │
        │  while queue not empty:  │
        │    port = queue.get()    │
        │    scan_port(port)       │
        │    if open → lock →      │
        │      open_ports.append() │
        └──────────────────────────┘
```

**Stack tecnico:**
- `socket.AF_INET` + `socket.SOCK_STREAM` → connessione TCP standard
- `threading.Thread` → esecuzione concorrente
- `queue.Queue` → distribuzione thread-safe dei task
- `threading.Lock` → scrittura sicura su `open_ports`

---

## ⚠️ Disclaimer

> Questo strumento è sviluppato **esclusivamente a scopo educativo e di apprendimento**.  
> Usalo **solo su sistemi di tua proprietà** o per i quali hai **esplicita autorizzazione scritta**.  
> La scansione non autorizzata di reti o sistemi è **illegale** in molti paesi.  
> L'autore non si assume alcuna responsabilità per usi impropri.

---

## 🗺️ Roadmap

- [X] Argomenti CLI con `argparse` (target, range, threads, timeout)
- [X] Banner grabbing per identificare i servizi
- [ ] Output su file `.json` / `.txt`
- [X] Progress bar con `tqdm`
- [ ] Supporto UDP scan
- [ ] Report HTML dei risultati

---

## 👤 Author

**Alessandro De Luca**

[![Portfolio](https://img.shields.io/badge/Portfolio-aledev746.github.io-5b9bd5?style=flat-square)](https://aledev746.github.io)
[![GitHub](https://img.shields.io/badge/GitHub-aledev746-383880?style=flat-square&logo=github)](https://github.com/aledev746)
[![Email](https://img.shields.io/badge/Email-alexdl0418%40gmail.com-c8dff0?style=flat-square)](mailto:alexdl0418@gmail.com)

---

## 📄 License

Distribuito sotto licenza **MIT**. Vedi [`LICENSE`](LICENSE) per i dettagli.

---

<div align="center">
  <sub>Built with ❤️ and Python · Palermo, Italia</sub>
</div>
