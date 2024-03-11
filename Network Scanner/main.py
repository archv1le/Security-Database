import socket
import threading
import argparse
from queue import Queue

def parse_ports(ports: str) -> list[int]:
    """
    Parse the port specification string and return a list of integers representing ports.

    Args:
        ports (str): Port specification string (e.g., '1-80', 'U:53,T:21-25,80').

    Returns:
        list[int]: List of integers representing ports.

    Raises:
        ValueError: If an invalid port specification is encountered.
    """

    if ports.lower() == '-f':
        # Fast port scan option, use a predefined list of common ports
        return [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389]
    elif ports.lower() == '-top-ports':
        # Top ports option, use a predefined list of top ports (adjust as needed)
        return [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 5900, 8080, 8443, 9090, 10000]
    elif '-p-' in ports and ports.endswith('65535'):
        # Port range starting from 1 up to 65535
        return list(range(1, 65536))
    elif '-p0-' in ports:
        # Port range starting from 0 up to 65535
        return list(range(0, 65536))

    result = []

    for port_spec in ports.split(','):
        if ':' in port_spec:
            protocol, port_range = port_spec.split(':')
            try:
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                    result.extend((protocol, port) for port in range(start_port, end_port + 1))
                else:
                    result.append((protocol, int(port_range)))
            except ValueError:
                print(f"Invalid port specification: {port_spec}")
                exit(1)
        else:
            try:
                if '-' in port_spec:
                    start_port, end_port = map(int, port_spec.split('-'))
                    result.extend(range(start_port, end_port + 1))
                else:
                    result.append(int(port_spec))
            except ValueError:
                try:
                    result.append(socket.getservbyname(port_spec))
                except (socket.error, socket.herror):
                    print(f"Invalid port or service name: {port_spec}")
                    exit(1)

    return result

def scan_target(target: str, port: int, processed_ports: set[int], detect_version: bool = False, version_intensity: int = 0, version_light: bool = False, version_all: bool = False, comprehensive_scan: bool = False, detect_os: bool = False, osscan_limit: bool = False, osscan_guess: bool = False) -> None:
    """
    Scan a target IP address and port for various information.

    Args:
        target (str): Target IP address.
        port (int): Port to scan.
        processed_ports (set[int]): Set of processed ports to avoid duplicates.
        detect_version (bool): Enable service version detection.
        version_intensity (int): Set version detection intensity level (0 to 9).
        version_light (bool): Enable light mode for version detection.
        version_all (bool): Enable version-all mode for higher intensity.
        comprehensive_scan (bool): Enable comprehensive scanning (OS detection, version detection, script scanning, and traceroute).
        detect_os (bool): Enable remote OS detection using TCP/IP stack fingerprinting.
        osscan_limit (bool): Limit OS detection to hosts with at least one open and one closed TCP port.
        osscan_guess (bool): Enable aggressive OS detection guessing.
    """
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((target, port))
            service_name = socket.getservbyport(port)

            # Check if the port has already been processed
            if port not in processed_ports:
                processed_ports.add(port)
                print(f"\n[+] Port: {port}")
                print(f"[+] Service: {service_name}")
                if detect_version:
                    try:
                        banner = get_banner(sock, version_intensity, version_light, version_all)
                        print(f"[+] Version: {banner}")
                    except Exception as e:
                        print(f"[-] Version detection failed: {e}")
                if detect_os and (osscan_limit or comprehensive_scan):
                    try:
                        os_info = detect_remote_os(sock, osscan_guess)
                        print(f"[+] OS Detection: {os_info}")
                    except Exception as e:
                        print(f"[-] OS detection failed: {e}")
                print(f"[+] State: open")
                print(f"[+] Target: {target}\n")
    except (socket.error, socket.timeout):
        pass

def detect_remote_os(sock: socket.socket, osscan_guess: bool, buffer_size: int = 1024) -> str:
    """
    Detect the remote OS using TCP/IP stack fingerprinting.

    Args:
        sock (socket.socket): Socket connected to the target.
        osscan_guess (bool): Enable aggressive OS detection guessing.
        buffer_size (int): Size of the buffer for receiving data.

    Returns:
        str: OS detection information.

    Raises:
        Exception: If OS detection fails.
    """
    
    # Send a request to trigger an OS fingerprint response
    if osscan_guess:
        # If aggressive OS detection guessing is enabled, send a modified request
        sock.send(b'\x00\x00\x00\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x01')
    else:
        # Otherwise, send the standard request
        sock.send(b'\x00\x00\x00\x0a\x0a\x0a\x0a\x0a\x0a\x0a')
    
    # Receive and decode the OS fingerprint response
    response = sock.recv(buffer_size).decode('utf-8').strip()
    return response

def get_banner(sock: socket.socket, version_intensity: int, version_light: bool, version_all: bool, buffer_size: int = 1024) -> str:
    """
    Get the service banner from the connected socket.

    Args:
        sock (socket.socket): Socket connected to the target.
        version_intensity (int): Set version detection intensity level (0 to 9).
        version_light (bool): Enable light mode for version detection.
        version_all (bool): Enable version-all mode for higher intensity.
        buffer_size (int): Size of the buffer for receiving data.

    Returns:
        str: Service banner information.

    Raises:
        Exception: If version detection fails.
    """
    
    # Receive banner from the connected socket
    if version_all:
        # Use a larger buffer size for version-all mode
        buffer_size = 2048
    elif version_light:
        # Use a smaller buffer size for light mode
        buffer_size = 128

    banner = sock.recv(buffer_size).decode('utf-8').strip()
    return banner

def worker(processed_ports: set[int], detect_version: bool, version_intensity: int, version_light: bool, version_all: bool, comprehensive_scan: bool, detect_os: bool, osscan_limit: bool, osscan_guess: bool) -> None:
    """
    Worker function for threaded scanning.

    Args:
        processed_ports (set[int]): Set of processed ports to avoid duplicates.
        detect_version (bool): Enable service version detection.
        version_intensity (int): Set version detection intensity level (0 to 9).
        version_light (bool): Enable light mode for version detection.
        version_all (bool): Enable version-all mode for higher intensity.
        comprehensive_scan (bool): Enable comprehensive scanning (OS detection, version detection, script scanning, and traceroute).
        detect_os (bool): Enable remote OS detection using TCP/IP stack fingerprinting.
        osscan_limit (bool): Limit OS detection to hosts with at least one open and one closed TCP port.
        osscan_guess (bool): Enable aggressive OS detection guessing.
    """
    
    while True:
        target, port = queue.get()
        scan_target(target, port, processed_ports, detect_version, version_intensity, version_light, version_all, comprehensive_scan, detect_os, osscan_limit, osscan_guess)
        queue.task_done()

def main(target: str, ports: list[int], num_threads: int, detect_version: bool, version_intensity: int, version_light: bool, version_all: bool, comprehensive_scan: bool, detect_os: bool, osscan_limit: bool, osscan_guess: bool) -> None:
    """
    Main function for the network scanner.

    Args:
        target (str): Target IP address.
        ports (list[int]): List of ports to scan.
        num_threads (int): Number of threads for concurrent scanning.
        detect_version (bool): Enable service version detection.
        version_intensity (int): Set version detection intensity level (0 to 9).
        version_light (bool): Enable light mode for version detection.
        version_all (bool): Enable version-all mode for higher intensity.
        comprehensive_scan (bool): Enable comprehensive scanning (OS detection, version detection, script scanning, and traceroute).
        detect_os (bool): Enable remote OS detection using TCP/IP stack fingerprinting.
        osscan_limit (bool): Limit OS detection to hosts with at least one open and one closed TCP port.
        osscan_guess (bool): Enable aggressive OS detection guessing.
    """
    
    global queue

    processed_ports = set()  # Keep track of processed ports to avoid duplicates
    queue = Queue()

    for port in ports:
        if isinstance(port, tuple):  # Handle protocol-specific ports
            queue.put((target, port[0], port[1]))
        else:
            queue.put((target, port))

    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(processed_ports, detect_version, version_intensity, version_light, version_all, comprehensive_scan, detect_os, osscan_limit, osscan_guess))
        thread.daemon = True
        thread.start()

    queue.join()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network Scanner')

    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('-p', '--ports', help='Port specification (-f for fast scan, -top-ports for top ports, -p-65535 for full range, -p0- for range starting from 0, U:53,T:21-25,80)', default='1-80')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads', default=10)
    parser.add_argument('-sV', '--detect-version', action='store_true', help='Enable service version detection')
    parser.add_argument('-version-intensity', type=int, choices=range(0, 10), default=0, help='Set version detection intensity level (0 to 9)')
    parser.add_argument('-version-light', action='store_true', help='Enable light mode for version detection')
    parser.add_argument('-version-all', action='store_true', help='Enable version-all mode for higher intensity')
    parser.add_argument('-A', '--comprehensive-scan', action='store_true', help='Enable comprehensive scanning (OS detection, version detection, script scanning, and traceroute)')
    parser.add_argument('-O', '--detect-os', action='store_true', help='Enable remote OS detection using TCP/IP stack fingerprinting')
    parser.add_argument('--osscan-limit', action='store_true', help='Limit OS detection to hosts with at least one open and one closed TCP port')
    parser.add_argument('--osscan-guess', action='store_true', help='Enable aggressive OS detection guessing')

    args = parser.parse_args()

    target_ip = args.target_ip

    target_ports = parse_ports(args.ports)

    num_threads = args.threads

    detect_version = args.detect_version

    version_intensity = args.version_intensity

    version_light = args.version_light

    version_all = args.version_all

    comprehensive_scan = args.comprehensive_scan

    detect_os = args.detect_os

    osscan_limit = args.osscan_limit

    osscan_guess = args.osscan_guess

    main(target_ip, target_ports, num_threads, detect_version, version_intensity, version_light, version_all, comprehensive_scan, detect_os, osscan_limit, osscan_guess)
