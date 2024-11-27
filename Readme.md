# JWT PortSwigger Lab Solver

This project is a tool for solving JWT-related labs from PortSwigger.

## Installation

1. Clone the repository:
 ```bash
git clone https://github.com/yourusername/jwt-portswigger-lab-solver.git
```

2. Navigate to the project directory:
```bash
cd jwt-portswigger-lab-solver
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script with the following command:

```bash
python3 jwt-attack.py -s 'https://example.com/' -x '127.0.0.1:8080' -i --delete
```

Replace `https://example.com/` with the target website URL.

## Options

- `-u`, `--username`: Username to authenticate with (default: wiener)
- `-p`, `--password`: Password to authenticate with (default: peter)
- `-s`, `--website`: Base URL of the target website
- `-x`, `--proxy`: Proxy server to use (e.g., 127.0.0.1:8080)
- `-i`, `--ignore-cert`: Ignore SSL certificate validation
- `-d`, `--delete`: Delete Carlos
- `-w`, `--wordlist`: Path to JWT secrets wordlist file

