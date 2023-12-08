import socket
import threading
import re
import logging
from colorama import Fore, Style, init
import argparse

init(autoreset=True)  # Initialize colorama
# service detection/security scanning
COMMON_PORTS_SERVICES = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    443: 'HTTPS',
    3389: 'RDP'
}

# Logging function
logging.basicConfig(
    level=logging.DEBUG,  # Change this to logging.DEBUG for more detailed logs
    format="%(asctime)s [%(levelname)s]: %(message)s",
    handlers=[
        logging.FileHandler("scan_log.txt"),
    ]
)
# save results to a file
def save_results_to_file(filename,targets):
    with open(filename, 'w') as file:
        for target in targets:
            file.write(f"Results for {target}:\n")
            for port in ip_results[target]['all_ports']:
                status = 'open' if port in ip_results[target]['open_ports'] else 'closed'
                service_name = COMMON_PORTS_SERVICES.get(port, "Unknown Service")
                file.write(f"Port {port} ({service_name}) is {status}.\n")
            file.write("\n")


ip_results = {}  # Dictionary to store results for each target IP
ip_results_lock = threading.Lock()  # Lock for updating ip_results
# ip validation
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
    # ip range validation 
def valid_ip_range(ip_range):
    start, end = ip_range.split('-')
    start_parts = list(map(int, start.split('.')))
    end_parts = list(map(int, end.split('.')))

    for i in range(4):
        if not (0 <= start_parts[i] <= 255) or not (0 <= end_parts[i] <= 255):
            return False

    return True 

def generate_ip_range(ip_range):
    start, end = ip_range.split('-')
    start_parts = list(map(int, start.split('.')))
    end_parts = list(map(int, end.split('.')))

    ips = []

    for i in range(start_parts[0], end_parts[0] + 1):
        for j in range(start_parts[1], end_parts[1] + 1):
            for k in range(start_parts[2], end_parts[2] + 1):
                for l in range(start_parts[3], end_parts[3] + 1):
                    ips.append(f"{i}.{j}.{k}.{l}")
    return ips                   


# port validation
def valid_port(arg):
    try:
        ports = parse_ports(arg)
        for port in ports:
            if not (0 < int(port) <= 65535):
                return False
        return True
    except ValueError:
        return False
# port parsing function
def parse_ports(arg):
    ports = []
    for part in arg.split(","):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports
# scanning function
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect((target, port))
        with ip_results_lock:
            ip_results[target]['open_ports'].add(port)
        logging.debug(f"Port {port} is open on {target}")
    except ConnectionRefusedError:
        with ip_results_lock:
            ip_results[target]['closed_ports'].add(port)
        logging.debug(f"Port {port} is closed on {target}")
    except socket.timeout:
        with ip_results_lock:
            ip_results[target]['closed_ports'].add(port)
        logging.debug(f"Port {port} is closed on {target}")
    except Exception as e:
        error_message = f"An error occurred while scanning port {port} on {target}: {e}"
        logging.error(error_message)
    finally:
        sock.close()
        
# display to user       
def display_port_status(target, port, status):
    service_name = COMMON_PORTS_SERVICES.get(port, "Unknown Service")
    if status == 'open':
        print(f"Port {port} ({service_name}) is {Fore.GREEN}open{Style.RESET_ALL} on {target}")
    elif status == 'closed':
        print(f"Port {port} ({service_name}) is {Fore.RED}closed{Style.RESET_ALL} on {target}")
# multi Threading
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
# scan multiple ips, scan ip range
def ip_input(ip_input_str):
    while True:
        ip_list = [ip.strip() for ip in ip_input_str.split(',')]

        if all(valid_ip(ip) or valid_ip_range(ip) for ip in ip_list):
            if '-' in ip_input_str:
                ips = generate_ip_range(ip_input_str)
            else:
                ips = ip_list

            print(f"You have entered valid IP addresses: {', '.join(ips)}")
            return ips
        else:
            raise argparse.ArgumentTypeError("Please enter valid IP addresses or range")
# define ports to scan for custom scan
def port_input():
    while True:
        port_range = input("Enter the port range (ex. '80-100' or '23,80,445') ")
        if valid_port(port_range):
            print("You have entered a valid port range")
            return port_range
        else:
            print("Please enter a valid port range")
# quick scan
def quick_scan(target, ports, scan_start_lock):
    thread_scan(target, ports, scan_start_lock)
# intense scan
def thorough_scan(target, port_range, scan_start_lock):
    ports = parse_ports(port_range)
    thread_scan(target, ports, scan_start_lock)
# custom scan list
def custom_scan(target, scan_start_lock):
    port_range = port_input()
    ports = parse_ports(port_range)
    thread_scan(target, ports, scan_start_lock)
    return port_range
# mulit threading
def thread_scan_wrapper(target, port, scan_start_lock):
    thread_scan(target, port, scan_start_lock)

def main(): # user friendly cli
    parser = argparse.ArgumentParser(description='TrashMap Scanner Made By Liam Smydo and Spencer Lightfoot')
    parser.add_argument('-t', '--target', type=ip_input, help="Target IPs or ranges (ex. '192.168.1.1,192.168.1.2' or '192.168.1.1-192.168.1.10')", default='127.0.0.1')
    parser.add_argument('-s', '--scan-type', help='Scan Type q = quick (Common Ports), t = thorough (All ports) c = custom)', default='q')
    parser.add_argument('-o', '--output', help='"Enter the filename to save results (include extension, e.g., "results.txt"): "', default='results.txt') # output customization
    args = parser.parse_args()
    ip_input_str = args.target
    scan_mode = args.scan_type
    global ip_results
    processed_ips = set()  # To track processed IPs
    targets = args.target

    for target in targets:
        if target not in processed_ips:
            processed_ips.add(target)
            ip_results[target] = {'open_ports': set(), 'closed_ports': set(), 'all_ports': set()}

            

            scan_start_lock = threading.Lock()
            # scan modes
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

            # port filtering
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
                    display_port_status(target, port, 'open')
                    printed_ports.add(port)
                elif port in ip_results[target]['closed_ports'] and port not in ip_results[target]['open_ports'] and port not in printed_ports:
                    display_port_status(target, port, 'closed')
                    printed_ports.add(port)
    filename = args.output
    save_results_to_file(filename,targets)
if __name__ == '__main__':
    main()