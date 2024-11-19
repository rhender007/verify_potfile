# verify_potfile

A tool to verify various hash formats from hashcat potfiles.

## Installation

First clean any existing installations:
```bash
sudo pip uninstall verify-potfile verify_potfile verify-hashes verify_hashes -y --break-system-packages
sudo rm -f /usr/local/bin/verify-potfile /usr/local/bin/verify_potfile
sudo rm -rf *.egg-info
sudo rm -rf build/ dist/
```

Install build requirements:
```bash
sudo pip install build --break-system-packages
```

Build and install:
```bash
python3 -m build
sudo pip install dist/verify_potfile-0.1-py3-none-any.whl --break-system-packages
```

## Usage

```bash
verify_potfile hashcat.potfile
```

## Supported Hash Types

- MD4
- MD5
- SHA1
- SHA256
- SHA512
- Whirlpool (requires OpenSSL)
- MD5crypt
- NTLM
- PKZIP
- PDF
- MS Office

## Requirements

- Python 3.6+
- OpenSSL
- passlib
