# bgpeepr.py

**bgpeepr.py** is a command-line utility that performs fuzzy searches against the IPtoASN database to identify ASNs and associated CIDR ranges for a given company or organization. It supports exporting results to JSON and CSV formats, making it useful for reconnaissance, research, and network inventory work.

## Features

- Fuzzy search for ASNs based on organization name  
- Extraction of IPv4 CIDR blocks associated with each ASN  
- Export results to JSON or CSV   

## Requirements

- Python 3.6 or higher  
- Modules:
  - `requests`
  - `netaddr`

Install the required modules using:

```bash
pip install requests
pip install netaddr
```

## Usage

```bash
python3 bgpeepr.py <company> [options]
```

### Arguments

- `company` — The company or organization name to search for (case-insensitive fuzzy match)

### Options

- `-p`, `--prefixes` — Display associated IP prefix ranges in CIDR format
- `-l`, `--local FILE` - Use local IPtoASN file
- `-6`, `--ipv6` - Include IPv6 prefixes  
- `-oJ FILE`, `--json FILE` — Output results to a JSON file  
- `-oC FILE`, `--csv FILE` — Output results to a CSV file  

## Examples

```bash
python3 bgpeepr.py microsoft
python3 bgpeepr.py oracle -p
python3 bgpeepr.py amazon -p -oJ amazon.json -oC amazon.csv
```

## Output

The script prints:

- A list of matched ASNs and their associated organization names  
- Optionally, IPv4 and IPv6 CIDR ranges tied to each ASN  
- Optional JSON or CSV export for automation or archival  

## Author

axiom0x0 — OG Bash script (2015) and Python port (2025)
