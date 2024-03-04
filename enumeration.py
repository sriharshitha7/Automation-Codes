import nmap
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

def ping_sweep(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    # Convert the subnet to a list of IPs and remove the first host (usually the gateway)
    all_hosts = list(nm.all_hosts())
    if all_hosts:  # Check if the list is not empty
        all_hosts.remove(all_hosts[0])  # Remove the first host, which is typically the gateway
    # Filter only live hosts
    live_hosts = [host for host in all_hosts if nm[host].state() == 'up']
    return live_hosts


def scan_open_ports(host):
    nm = nmap.PortScanner()
    # Scan all ports from 1 to 65535
    nm.scan(hosts=host, arguments='-p 1-65535 -T4')  # Adjust -T4 if needed
    open_ports = []
    for proto in nm[host].all_protocols():
        lport = sorted(nm[host][proto].keys())
        for port in lport:
            open_ports.append((port, nm[host][proto][port]['name']))
    return open_ports

def get_web_title(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.title.string if soup.title else 'No Title Found'
    except Exception as e:
        return f"Error: {e}"

def main(subnet):
    print(f"Starting ping sweep on {subnet}")
    hosts = ping_sweep(subnet)
    print(f"Live hosts: {hosts}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        for host in hosts:
            print(f"\nScanning open ports for host: {host}")
            open_ports = executor.submit(scan_open_ports, host).result()
            for port, service in open_ports:
                print(f"Port {port}/tcp open ({service})")
                if service == 'http' or port in [80, 8080, 8000]:
                    title = executor.submit(get_web_title, f"http://{host}").result()
                    print(f"Web Title: {title}")
                elif service == 'https' or port in [443, 8443]:
                    title = executor.submit(get_web_title, f"https://{host}").result()
                    print(f"Web Title: {title}")

if __name__ == "__main__":
    subnet = "192.168.179.0/24"  # Example subnet, adjust as needed
    main(subnet)

