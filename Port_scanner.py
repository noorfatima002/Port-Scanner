import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            return port, "OPEN"
        else:
            return port, "CLOSED"

    except socket.timeout:
        return port, "TIMEOUT"

    except Exception as error:
        return port, f"ERROR: {error}"


def main():
    target = input("Enter target (use 127.0.0.1 for your own PC): ")

    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    log_file = "scan_results.txt"

    print("\nStarting TCP Port Scan...")
    print("-" * 40)

    with open(log_file, "w") as file:
        file.write("TCP PORT SCAN RESULTS\n")
        file.write("=" * 40 + "\n")
        file.write(f"Target: {target}\n")
        file.write(f"Time: {datetime.now()}\n")
        file.write("-" * 40 + "\n")

        ports = range(start_port, end_port + 1)

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(
                lambda port: scan_port(target, port),
                ports
            )

            for port, status in results:
                result_line = f"Port {port}: {status}"
                print(result_line)
                file.write(result_line + "\n")

        file.write("-" * 40 + "\n")
        file.write("Scan completed.\n")

    print("-" * 40)
    print("Scan completed.")
    print(f"Results saved in: {log_file}")


if __name__ == "__main__":
    main()