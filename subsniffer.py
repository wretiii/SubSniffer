import argparse
import concurrent.futures
import csv
import os
import socket
import sys
import threading
import time

import requests

try:
    import shodan
except ImportError:
    shodan = None

DEFAULT_ACTIVE_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                         993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]


def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None


def check_redirects(subdomain):
    last_error = None
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{subdomain}", timeout=5, allow_redirects=True)
            if response.history:
                return f"Redirects to {response.url}"
            return ""
        except requests.RequestException as exc:
            last_error = exc
            continue
    return f"Unreachable via http/https ({last_error})" if last_error else "Unreachable via http/https"


class ShodanRateLimiter:
    """Serializes Shodan calls across threads to respect the API's per-second limit."""

    def __init__(self, min_interval):
        self.min_interval = min_interval
        self.lock = threading.Lock()
        self.last_call = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call = time.monotonic()


def get_open_ports_shodan(shodan_api, rate_limiter, ip):
    rate_limiter.wait()
    try:
        host_info = shodan_api.host(ip)
        ports = sorted(host_info.get("ports", []))
        return ", ".join(map(str, ports)), None
    except shodan.APIError as exc:
        return "", f"shodan-error: {exc}"


def scan_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except OSError:
        return None


def active_port_scan(ip, ports, timeout=0.75):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(ports) or 1)) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return ", ".join(map(str, sorted(open_ports)))


def process_subdomain(subdomain, args, shodan_api, rate_limiter):
    ip = resolve_ip(subdomain)
    redirect_notes = check_redirects(subdomain)

    ports = ""
    port_source = ""
    if ip:
        if args.active:
            ports = active_port_scan(ip, args.ports, timeout=args.scan_timeout)
            port_source = "active-scan"
        elif shodan_api:
            ports, err = get_open_ports_shodan(shodan_api, rate_limiter, ip)
            port_source = "shodan" if not err else err

    print(f"Processed {subdomain}: IP={ip}, Ports={ports or '(none found)'}, Redirects={redirect_notes or '(none)'}")
    return {
        "Subdomain": subdomain,
        "IP Address": ip or "",
        "Open Ports": ports,
        "Port Source": port_source,
        "Redirect Notes": redirect_notes,
    }


def load_subdomains(input_file):
    with open(input_file, "r") as file:
        seen = set()
        subdomains = []
        for line in file:
            subdomain = line.strip()
            if subdomain and subdomain not in seen:
                seen.add(subdomain)
                subdomains.append(subdomain)
    return subdomains


def main():
    parser = argparse.ArgumentParser(description="Resolve subdomains, check redirects, and enumerate open ports.")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-i", "--input", help="Input file containing subdomains.")
    target_group.add_argument("-d", "--domain", help="Look up a single subdomain instead of reading from a file.")
    parser.add_argument("-o", "--output", default="output.csv", help="Output CSV file (default: output.csv)")
    parser.add_argument("--active", action="store_true",
                         help="Do a live TCP connect-scan of common ports instead of the passive Shodan lookup. "
                              "Sends packets directly to targets -- only use against hosts you're authorized to scan.")
    parser.add_argument("--ports", default=None,
                         help="Comma-separated list of ports to use with --active (default: a common-ports list)")
    parser.add_argument("--scan-timeout", type=float, default=0.75, help="Per-port timeout in seconds for --active scans (default: 0.75)")
    parser.add_argument("--threads", type=int, default=10, help="Number of subdomains to process concurrently (default: 10)")
    parser.add_argument("--api-key", default=None, help="Shodan API key (overrides SHODAN_API_KEY env var)")
    parser.add_argument("--shodan-delay", type=float, default=1.1, help="Minimum seconds between Shodan API calls (default: 1.1, free tier is 1 req/sec)")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.ports:
        try:
            args.ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("Error: --ports must be a comma-separated list of integers.", file=sys.stderr)
            sys.exit(1)
    else:
        args.ports = DEFAULT_ACTIVE_PORTS

    if args.domain:
        subdomains = [args.domain.strip()]
    else:
        if not os.path.isfile(args.input):
            print(f"Error: input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        subdomains = load_subdomains(args.input)

    if not subdomains:
        print("No subdomains found in input file.", file=sys.stderr)
        sys.exit(1)

    shodan_api = None
    if args.active:
        print("Active scanning enabled: sending TCP connection attempts directly to targets. "
              "Ensure you are authorized to scan these hosts.")
    else:
        shodan_key = args.api_key or os.environ.get("SHODAN_API_KEY")
        if shodan_key:
            if shodan is None:
                print("Error: a Shodan API key was provided but the 'shodan' package isn't installed. "
                      "Run: pip install shodan", file=sys.stderr)
                sys.exit(1)
            shodan_api = shodan.Shodan(shodan_key)
        else:
            print("No Shodan API key found (set --api-key or SHODAN_API_KEY, or use --active for a live port scan). "
                  "Skipping port lookups.")

    rate_limiter = ShodanRateLimiter(args.shodan_delay)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_subdomain, s, args, shodan_api, rate_limiter) for s in subdomains]
        for future in futures:
            results.append(future.result())

    with open(args.output, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Subdomain", "IP Address", "Open Ports", "Port Source", "Redirect Notes"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
