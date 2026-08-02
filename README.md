# SubSniffer

Scans a list of subdomains, resolves their IP addresses, checks for open ports, and verifies whether the subdomains redirect to another URL.

Port discovery has two modes:
- **Passive (default)**: looks up open ports via [Shodan](https://www.shodan.io/)'s existing internet-wide scan data. Doesn't touch the target directly, but data can be stale (Shodan's own scan cache) and requires a Shodan API key.
- **Active (`--active`)**: does a live TCP connect-scan of a common-ports list directly against each resolved IP. No API key needed and gives current results, but it sends packets straight to the target — only use it against hosts you're authorized to scan.

## Requirements
- Python 3.6 or higher.
- External libraries: `requests`, `shodan`.
```bash
pip install -r requirements.txt
```
- A Shodan API key is only needed for the default passive mode. Not required if you use `--active`.

## Usage
```bash
python3 subsniffer.py -i subdomains.txt
```

Options:
```
-i, --input           Input file containing subdomains.                         [required]
-o, --output           Output CSV file (default: output.csv)
--active                Do a live TCP connect-scan instead of the passive Shodan lookup.
                        Sends packets directly to targets -- only use against hosts
                        you're authorized to scan.
--ports                 Comma-separated list of ports to use with --active
                        (default: a common-ports list)
--scan-timeout          Per-port timeout in seconds for --active scans (default: 0.75)
--threads               Number of subdomains to process concurrently (default: 10)
--api-key               Shodan API key (overrides the SHODAN_API_KEY environment variable)
--shodan-delay          Minimum seconds between Shodan API calls (default: 1.1,
                        the free tier is limited to 1 request/second)
```

### Passive mode (Shodan)

```bash
export SHODAN_API_KEY="your-shodan-api-key"
python3 subsniffer.py -i subdomains.txt
```

If no key is configured, SubSniffer still resolves IPs and checks redirects, and just skips the port lookup with a message.

### Active mode

```bash
python3 subsniffer.py -i subdomains.txt --active
```

No sudo/root is required — SubSniffer only makes standard outbound TCP connections and DNS lookups.

## Output

Results print to the console as each subdomain is processed, and are written to a CSV (`Subdomain, IP Address, Open Ports, Port Source, Redirect Notes`). `Port Source` indicates whether ports came from `shodan` or `active-scan`, or shows the Shodan error message if the lookup failed for that host.
