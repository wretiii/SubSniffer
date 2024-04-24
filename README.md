# SubSniffer
Scans a list of subdomains, resolves their IP addresses, checks for open ports using Shodan, and verifies if the subdomains redirect to another URL.

## Requirements
- Python 3.6 or higher.
- An active API key from [Shodan](https://www.shodan.io/).
- External libraries: `requests`, `shodan`.
```bash
pip install requests shodan
```

## Usage
```bash
sudo python3 subsniffer.py -i subdomains.txt

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file containing subdomains.
```
