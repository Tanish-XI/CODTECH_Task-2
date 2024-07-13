import nmap
import requests

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')  # Scanning first 1024 ports
    result = {}
    for host in nm.all_hosts():
        result[host] = {}
        result[host]['state'] = nm[host].state()
        result[host]['ports'] = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = {
                    'port': port,
                    'state': nm[host][proto][port]['state']
                }
                result[host]['ports'].append(port_info)
    return result

def check_server_version(url):
    try:
        response = requests.head(url)
        server = response.headers.get('Server', 'Unknown')
        return f'Server version: {server}'
    except requests.RequestException as e:
        return f'Error checking server version: {e}'

def check_https(url):
    if not url.startswith('https'):
        return 'Warning: HTTPS not enabled'
    else:
        return 'HTTPS is enabled'

def main():
    target = input("Enter the target IP or hostname for network scan: ")
    network_result = scan_network(target)
    print("Network Scan Results:")
    for host, data in network_result.items():
        print(f'Host: {host}, State: {data["state"]}')
        for port in data['ports']:
            print(f'  Port: {port["port"]}, State: {port["state"]}')
    
    website = input("Enter the website URL (including http/https): ")
    server_version = check_server_version(website)
    https_check = check_https(website)
    print("Web Check Results:")
    print(server_version)
    print(https_check)

if __name__ == "__main__":
    main()
