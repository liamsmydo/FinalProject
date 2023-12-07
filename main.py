import socket
import threading
import re
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s]: %(message)s",
    handlers=[
        logging.FileHandler("scan_log.txt"),
        logging.StreamHandler()
    ]
)

ip_results = {}  # Dictionary to store results for each target IP
ip_results_lock = threading.Lock()  # Lock for updating ip_results

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect((target, port))
        with ip_results_lock:
            ip_results[target]['open_ports'].add(port)
    except ConnectionRefusedError:
        with ip_results_lock:
            ip_results[target]['closed_ports'].add(port)
    except socket.timeout:
        with ip_results_lock:
            ip_results[target]['closed_ports'].add(port)
    except Exception as e:
        error_message = f"An error occurred while scanning port {port} on {target}: {e}"
        logging.error(error_message)
    finally:
        sock.close()

def thread_scan(target, ports, scan_start_lock):
    threads = []

    def scan_port_wrapper(port):
        scan_port(target, port)

    with scan_start_lock:
        for port in ports:
            thread = threading.Thread(target=scan_port_wrapper, args=(port,))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

def ip_input():
    while True:
        targets = input("Enter the target IPs or hostnames separated by commas: ")
        target_list = [t.strip() for t in targets.split(',')]
        if all(valid_ip(target) for target in target_list):
            print("You have entered valid IP addresses")
            return target_list
        else:
            print("Please enter valid IP addresses")

def port_input():
    while True:
        port_range = input("Enter the port range (ex. '80-100' or '23,80,445') ")
        if valid_port(port_range):
            print("You have entered a valid port range")
            return port_range
        else:
            print("Please enter a valid port range")

def quick_scan(target, ports, scan_start_lock):
    thread_scan(target, ports, scan_start_lock)

def thorough_scan(target, port_range, scan_start_lock):
    ports = parse_ports(port_range)
    thread_scan(target, ports, scan_start_lock)

def custom_scan(target, scan_start_lock):
    port_range = port_input()
    ports = parse_ports(port_range)
    thread_scan(target, ports, scan_start_lock)
    return port_range

def thread_scan_wrapper(target, port, scan_start_lock):
    thread_scan(target, port, scan_start_lock)

def main():
    global ip_results
    processed_ips = set()  # To track processed IPs
    targets = ip_input()

    for target in targets:
        if target not in processed_ips:
            processed_ips.add(target)
            ip_results[target] = {'open_ports': set(), 'closed_ports': set(), 'all_ports': set()}

            # Scan mode options
            scan_mode = input(f"\nChoose a scan mode for target {target}: "
                              "\n(Q)uick Scan (Common Ports)"
                              "\n(T)horough Scan (Entire Port Range)"
                              "\n(C)ustom Scan (Specify Port Range) ").lower()

            scan_start_lock = threading.Lock()

            if scan_mode == 'q':
                common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389]
                quick_scan(target, common_ports, scan_start_lock)
            elif scan_mode == 't':
                port_range = "1-65535"  # Entire port range
                thorough_scan(target, port_range, scan_start_lock)
            elif scan_mode == 'c':
                port_range = custom_scan(target, scan_start_lock)
            else:
                print("Invalid scan mode. Exiting.")
                return

            if scan_mode != 'q':
                ports = []  # Specifies the port list to scan
                for part in port_range.split(","):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))

                with scan_start_lock:
                    print(f"Scanning ports {ports} on target {target}... \n")

                num_threads = 4
                threads = []

                for i in range(num_threads):
                    start = i * len(ports) // num_threads
                    end = (i + 1) * len(ports) // num_threads
                    thread = threading.Thread(target=thread_scan_wrapper,
                                              args=(target, ports[start:end], scan_start_lock))
                    threads.append(thread)
                    thread.start()

                for thread in threads:
                    thread.join()

            ip_results[target]['all_ports'].update(ip_results[target]['open_ports'])
            ip_results[target]['all_ports'].update(ip_results[target]['closed_ports'])

            # user chooses filter
            filter_option = input("Filter options: (O)pen Ports, (C)losed Ports, (A)ll Ports: ").lower()

            if filter_option == 'o':
                filtered_ports = sorted(ip_results[target]['open_ports'])
            elif filter_option == 'c':
                filtered_ports = sorted(ip_results[target]['closed_ports'])
            elif filter_option == 'a':
                filtered_ports = sorted(ip_results[target]['all_ports'])
            else:
                print("Invalid filter option. Displaying all ports.")
                filtered_ports = sorted(ip_results[target]['all_ports'])

            printed_ports = set()  # To track printed ports
            for port in filtered_ports:
                if port in ip_results[target]['open_ports'] and port not in ip_results[target]['closed_ports'] and port not in printed_ports:
                    print(f"Port {port} is open on {target}")
                    printed_ports.add(port)
                elif port in ip_results[target]['closed_ports'] and port not in ip_results[target]['open_ports'] and port not in printed_ports:
                    print(f"Port {port} is closed on {target}")
                    printed_ports.add(port)

if __name__ == '__main__':
    main()