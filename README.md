# SOC I/O

A python package made of cybersecurity tools for accelerating triage based on OSINT APIs.

## Tools

| Command | Input | Purpose | Status |
|---|---|---|---|
| `socio --help` | N/A | Manual of socio's tools | *Completed* |
| `socio email` | `.eml` | Email analysis of protocols, URLs, domains, IPs and attachments | *In Progress* |
| `socio signins` | `.csv` | Entra ID sign-in log reputation for IPs | *In Progress* |

## Requirements

- Python >= 3.12

## Installation

```bash
git clone https://github.com/jisumov/socio.git
cd socio
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

<img src="https://raw.githubusercontent.com/jisumov/socio/main/socio.png" alt="SOC I/O cover" width="1024">