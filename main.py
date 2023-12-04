import socket
import threading
import re


print_lock = threading.Lock()
open_ports = set()
closed_ports = set()
all_ports = []

def valid_ip(arg):
    ip_pattern = re.compile(
        r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
    )
    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    )

    if ip_pattern.match(arg) or hostname_pattern.match(arg):
        return True
    else:
        return False

def valid_port(arg):
    try:
        ports = parse_ports(arg)
        for port in ports:
            if not (0 < int(port) <= 65535):
                return False
        return True
    except ValueError:
        return False

def parse_ports(arg):
    ports = []
    for part in arg.split(","):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def scan_port(target, port):
    try:
        sock =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect((target, port))
        with print_lock:
          open_ports.add(port)
    except ConnectionRefusedError:
        with print_lock:
           closed_ports.add(port)
    except socket.timeout:
        with print_lock:
           closed_ports.add(port)
    except Exception as e:
        with print_lock:
            print(f"An error occurred while scanning port {port}: {e}\n")
    finally:
        sock.close()

def thread_scan(target, ports):
    for port in ports:
        scan_port(target, port)
        
def ip_input():
    while True:
        target = input("Enter the target IP or hostname: ")
        if valid_ip(target):
            print ("you have entered a valid ip address")
            return target
        else:
            print ("please enter a valid ip address")

def port_input():
    while True:
        port_range = input("Enter the port range (ex. '80-100' or '23,80,445') ")
        if valid_port(port_range):
            print ("you have entered a valid port range")
            return port_range
        else:
            print ("please enter a valid port range")
def quick_scan(target, ports):
    thread_scan(target, ports)
    for thread in threading.enumerate():  # Wait for all threads to finish
        if thread is not threading.current_thread():
            thread.join()

def thorough_scan(target, port_range):
    ports = parse_ports(port_range)
    thread_scan(target, ports)

def custom_scan(target):
    port_range = port_input()
    ports = parse_ports(port_range)
    thread_scan(target, ports)
    return port_range

def thread_scan_wrapper(target, port):
    thread_scan(target, port)

def main():
    target = ip_input()
     # Scan mode options
    print("Scan Modes:")
    print("  (Q)uick Scan (Common Ports)")
    print("  (T)horough Scan (Entire Port Range)")
    print("  (C)ustom Scan (Specify Port Range)")
    scan_mode = input("Choose a scan mode: ").lower()

    if scan_mode == 'q':
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389]
        quick_scan(target, common_ports)
        ports = common_ports
    elif scan_mode == 't':
        port_range = "1-65535"  # Entire port range
        thorough_scan(target, port_range)
    elif scan_mode == 'c':
        port_range = custom_scan(target)
    else:
        print("Invalid scan mode. Exiting.")
        return
    if scan_mode != 'q':
        ports = []                          #Specifies the port list to scan
        for part in port_range.split(","):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
   
    print (f"scanning ports {ports} on target {target}... \n")

    num_threads = 4
    threads =[]

    for i in range(num_threads):
        start = i * len(ports) // num_threads
        end = (i + 1) * len(ports) // num_threads
        thread = threading.Thread(target=thread_scan_wrapper, args=(target, ports[start:end]))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    
    all_ports.extend(open_ports)
    all_ports.extend(closed_ports)
    all_ports.sort() 
    # user chooses filter
    filter_option = input("Filter options: (O)pen Ports, (C)losed Ports, (A)ll Ports: ").lower()

    if filter_option == 'o':
        filtered_ports = sorted(open_ports)
    elif filter_option == 'c':
        filtered_ports = sorted(closed_ports)
    elif filter_option == 'a':
        filtered_ports = all_ports
    else:
        print("Invalid filter option. Displaying all ports.")
        filtered_ports = all_ports

    for port in filtered_ports:
            if port in open_ports:
                print(f"Port {port} is open")
            else:
                print(f"Port {port} is closed")   
          
                
if __name__ == '__main__':
    main()