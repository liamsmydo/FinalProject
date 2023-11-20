import socket
import threading
import multiprocessing


print_lock = threading.Lock()


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

def main():
    target = input("Enter the target IP or hostname: ")
    port_range = input("Enter the port range (ex. '80-100' or '23,80,445') ")

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


if name == "main":
    main()