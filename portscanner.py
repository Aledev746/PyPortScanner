import socket
import json
import threading
import argparse
from queue import Queue
from typing import List
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

# Let's define all the variables that we will use 
output_format = None

progress_bar = None # To see how far along the scan is

progress_lock = threading.Lock()
coda: Queue[tuple[str, int]] = Queue() #Where we insert all the ports that we have found
open_ports:List[tuple[str,int,str,str]] = [] # List with all the open ports,their banner, status(open,closed) and type(TCP or UDP)
lock = threading.Lock()
target = "127.0.0.1"
sock_timeout = SOCK_TIMEOUT

def portscan(port:int)-> tuple[bool,str]: 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #with [AF_INET] We are saying that this is an internet bound socket, with [SOCK_STREAM] we are saying that we are using TCP as the protocol
        sock.settimeout(sock_timeout)
        sock.connect((target,port))
        
        #Let's grab the banner of the port
        banner = sock.recv(1024).decode("utf-8",errors = "ignore").strip()
        sock.close()
        return True,banner
    
    except(socket.timeout, ConnectionRefusedError, OSError):
        return False,""


#Function for UDP scan type
def udp_scan(port:int)-> tuple[bool, str, str]:
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.settimeout(sock_timeout)


        #payload minimale
        sock.sendto(b"\x00",(target,port))
        data, _ = sock.recvfrom(1024)
        banner = data.decode("utf-8",errors = "ignore").strip()
        sock.close()

        return True,banner,"open"
    
    except socket.timeout:
        return False,"","open|filtered"
    
    except OSError:
        return False,"","closed"






# Let's initialize the queue
def fill_queue(port_list: range,scan_type:str)-> None: 
    for port in port_list:
        if scan_type in ("TCP","BOTH"):
            coda.put(("TCP",port))
        if scan_type in ("UDP","BOTH"):
            coda.put(("UDP",port))



def worker()-> None: 
    global progress_bar
    while not coda.empty():
        protocol,port = coda.get()
        if protocol == "TCP":
            is_open,banner = portscan(port)
            status = "open" if is_open else "closed"
        
        else:
            is_open,banner,status = udp_scan(port)
        
        if is_open or (protocol == "UDP" and status == "open|filtered"):
            with lock:
                open_ports.append((protocol,port,status,banner))


        coda.task_done()
        if progress_bar is not None:
            with progress_lock:
                progress_bar.update(1)



# Main Function where we insert the parser for all the type of args that we accept from the terminal
def main() -> None:
    parser = argparse.ArgumentParser(description= "Python PortScanner")
    parser.add_argument("target", help="IP address or hostname of the target (EX: 192.168.1.1)")
    parser.add_argument("-r", "--range", default="1-1024", help="Port range to scan, format START-END (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=NUM_THREADS, help=f"Number of worker threads (default: {NUM_THREADS})")
    parser.add_argument("--timeout", type=float, default=SOCK_TIMEOUT, help=f"Socket timeout in seconds (default: {SOCK_TIMEOUT})")
    parser.add_argument("--output", choices=["txt", "json"], default=None, help="Save results to file format: txt or json")
    parser.add_argument("--scan-type",choices=["TCP","UDP","BOTH"],default="TCP",help="Type of scan : TCP , UDP , BOTH")
    args = parser.parse_args()

    # Initilize the global variables with ther args accepted from the command line
    global target, sock_timeout, output_format
    output_format = args.output
    target = args.target
    sock_timeout = args.timeout

    try:
        start_port, end_port = map(int, args.range.split("-", 1))
    except ValueError:
        parser.error("Port range must use START-END format, for example 1-1024")

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        parser.error("Port range must be within 1-65535 and START must be <= END")

    fill_queue(range(start_port, end_port + 1), args.scan_type)

    #Initialize the progress bar from the tqdm library
    global progress_bar

    total_ports = end_port - start_port + 1

    total_tasks = total_ports * 2 if args.scan_type == "BOTH" else total_ports

    progress_bar = tqdm(total=total_tasks, desc=f"Scanning {target}", unit="port")

   
   
    #Let's create the Threads
    threads = [
        threading.Thread(target=worker)
        for _ in range(args.threads)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if progress_bar is not None:  # type: ignore
        progress_bar.close()

   
    # Let's sort the list of open ports for better output 
    sorted_open_ports = sorted(open_ports, key=lambda x: (x[0], x[1]))


    
    # OUTPUT
    if output_format is None:
        for protocol, port, status, banner in sorted_open_ports:
            print(f"{protocol.upper()} {port} -> {status} {('- ' + banner) if banner else ''}")


   
    #OUTPUT TYPE .TXT
    if output_format == "txt":
        with open("portscanner.txt", "w", encoding="utf-8") as file:
            for protocol,port, status,banner in sorted_open_ports:
                file.write(f"{protocol.upper()} {port} -> {status} {('- ' + banner) if banner else ''}\n")
        print("Results saved to portscanner.txt")

   
   
    #OUTPUT TYPE .JSON
    if output_format == "json":
        results = [
            {"protocol": protocol, "port": port, "status": status, "banner": banner}
            for protocol, port, status, banner in sorted_open_ports
        ]
        data = {
            "target": target,
            "open_ports": results,
        }
        with open("portscanner.json", "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        print("Results saved to portscanner.json")



if __name__ == "__main__":
    print(ascii_art)
    main()