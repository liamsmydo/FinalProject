import socket
import threading
import re


print_lock = threading.Lock()

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
            print (f"Port {port} is open\n")
    except ConnectionRefusedError:
        with print_lock:
            print(f"Port {port} is closed\n")
    except socket.timeout:
        with print_lock:
            print(f"Port {port} timed out\n")
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

def main():
    target = ip_input()
    port_range = port_input()

    ports = []                          #Specifies the port list to scan
    for part in port_range.split(","):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    print(f"Scanning ports {ports} on {target}... \n")

    num_threads = 4
    threads =[]

    for i in range(num_threads): #Scans ports with mutiple threads
        start = i * len(ports) // num_threads
        end = (i+1) * len(ports) // num_threads
        thread = threading.Thread(target=thread_scan, args=(target, ports[start:end]))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()