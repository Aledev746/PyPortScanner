import socket
import threading
from queue import Queue
from typing import List
import argparse
from tqdm import tqdm

NUM_THREADS = 150
SOCK_TIMEOUT = 0.5
ascii_art = r"""
 /$$$$$$$  /$$     /$$ /$$$$$$$                       /$$      /$$$$$$                                                             
| $$__  $$|  $$   /$$/| $$__  $$                     | $$     /$$__  $$                                                            
| $$  \ $$ \  $$ /$$/ | $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$  | $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
| $$$$$$$/  \  $$$$/  | $$$$$$$//$$__  $$ /$$__  $$|_  $$_/  |  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
| $$____/    \  $$/   | $$____/| $$  \ $$| $$  \__/  | $$     \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
| $$          | $$    | $$     | $$  | $$| $$        | $$ /$$ /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
| $$          | $$    | $$     |  $$$$$$/| $$        |  $$$$/|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
|__/          |__/    |__/      \______/ |__/         \___/   \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
"""

progress_bar = None
progress_lock = threading.Lock()
coda:Queue = Queue() 
open_ports:List[tuple[int,str]] = []
lock = threading.Lock()
target = "127.0.0.1"
sock_timeout = SOCK_TIMEOUT


def portscan(port:int)-> tuple[bool,str]: 
    try:
        #Creiamo la socket
        #con [AF_INET] Stiamo dicendo che questa è una socket legata a Internet, con [SOCK_STREAM] stiamo dicendo che stiamo utilizzando come protocollo TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.settimeout(sock_timeout)
        sock.connect((target,port))
        #Banner Grabbing
        banner = sock.recv(1024).decode("utf-8",errors = "ignore").strip()
        sock.close()
        return True,banner
    
    except(socket.timeout, ConnectionRefusedError, OSError):
        return False,""


def fill_queue(port_list: range)-> None: 
    for port in port_list:
        coda.put(port)  


def worker()-> None: 
    global progress_bar
    while not coda.empty():
        port = coda.get() #type:ignore
        is_open,banner = portscan(port) #type: ignore
        if is_open:
            with lock:
                open_ports.append((port,banner)) # pyright: ignore[reportCallIssue]
        coda.task_done()
        if progress_bar is not None:
            with progress_lock:
                progress_bar.update(1)

thread_list = []


def main() -> None:
    parser = argparse.ArgumentParser(description= "Python PortScanner")
    parser.add_argument("target", help="IP address or hostname of the target (EX: 192.168.1.1)")
    parser.add_argument("-r", "--range", default="1-1024", help="Port range to scan, format START-END (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=NUM_THREADS, help=f"Number of worker threads (default: {NUM_THREADS})")
    parser.add_argument("--timeout", type=float, default=SOCK_TIMEOUT, help=f"Socket timeout in seconds (default: {SOCK_TIMEOUT})")
    args = parser.parse_args()

    global target, sock_timeout
    target = args.target
    sock_timeout = args.timeout

    try:
        start_port, end_port = map(int, args.range.split("-", 1))
    except ValueError as exc:
        parser.error("Port range must use START-END format, for example 1-1024")

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        parser.error("Port range must be within 1-65535 and START must be <= END")

    fill_queue(range(start_port, end_port + 1))
    global progress_bar
    progress_bar = tqdm(total= end_port - start_port + 1, desc=f"Scanning {target}", unit="port")

    threads = [
        threading.Thread(target=worker)
        for _ in range(args.threads)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()
        if progress_bar is not None: # type: ignore
            progress_bar.close()

    for port,banner in sorted(open_ports):
        print(f"Port: {port} is open -> {banner}")


if __name__ == "__main__":
    print(ascii_art)
    main()