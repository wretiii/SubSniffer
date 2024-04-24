import socket
import requests
import shodan
import csv
import argparse

# Configuration
shodan_api_key = 'Your_API_Key' # Add your Shodan API key here

# Initialize Shodan API
shodan_api = shodan.Shodan(shodan_api_key)

def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None

def check_redirects(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=5, allow_redirects=True)
        if response.history:
            return f"Redirects to {response.url}"
        return ""
    except requests.RequestException:
        return ""

def get_open_ports_shodan(ip):
    try:
        host_info = shodan_api.host(ip)
        ports = [port for port in host_info['ports']]
        ports.sort()  # Sorts the list of ports in ascending order
        return ", ".join(map(str, ports))
    except shodan.APIError:
        return ""

def main(input_file):
    # Load subdomains from file
    with open(input_file, 'r') as file:
        subdomains = [line.strip() for line in file]

    # Prepare CSV
    with open('output.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Subdomain', 'IP Address', 'Open Ports', 'Redirect Notes'])

        # Process each subdomain
        for subdomain in subdomains:
            ip = resolve_ip(subdomain)
            redirect_notes = check_redirects(subdomain)
            ports_shodan = get_open_ports_shodan(ip) if ip else ""

            # Output to CSV
            writer.writerow([subdomain, ip if ip else '', ports_shodan, redirect_notes])

            # Output to screen
            print(f"Processed {subdomain}: IP={ip}, Ports={ports_shodan}, Redirects={redirect_notes}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process subdomains from a file.')
    parser.add_argument('-i', '--input', required=True, help='Input file containing subdomains.')
    args = parser.parse_args()

    main(args.input)
