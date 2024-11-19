#!/usr/bin/env python3

import hashlib
import sys
import os
from passlib.hash import md5_crypt
from passlib.utils.md4 import md4
import re
import subprocess

def verify_md4(hash_part, plaintext):
    """Verify MD4 hash."""
    result = md4(plaintext.encode()).hexdigest().lower()
    hash_part = hash_part.lower()
    print(f"MD4: Generated {result}, Expected {hash_part}")
    return result == hash_part

def verify_sha1(hash_part, plaintext):
    """Verify SHA1 hash."""
    result = hashlib.sha1(plaintext.encode()).hexdigest().lower()
    hash_part = hash_part.lower()
    print(f"SHA1: Generated {result}, Expected {hash_part}")
    return result == hash_part

def verify_sha256(hash_part, plaintext):
    """Verify SHA256 hash."""
    result = hashlib.sha256(plaintext.encode()).hexdigest().lower()
    hash_part = hash_part.lower()
    print(f"SHA256: Generated {result}, Expected {hash_part}")
    return result == hash_part

def verify_sha512(hash_part, plaintext):
    """Verify SHA512 hash."""
    result = hashlib.sha512(plaintext.encode()).hexdigest().lower()
    hash_part = hash_part.lower()
    print(f"SHA512: Generated {result}, Expected {hash_part}")
    return result == hash_part

def verify_whirlpool(hash_part, plaintext):
    """Verify Whirlpool hash using openssl."""
    try:
        # Run openssl command
        cmd = ['openssl', 'dgst', '-whirlpool']
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=plaintext.encode())
        
        if proc.returncode != 0:
            print(f"OpenSSL error: {stderr.decode()}")
            return False
            
        # OpenSSL output format is "(stdin)= HASH"
        result = stdout.decode().strip().split('= ')[1].lower()
        hash_part = hash_part.lower()
        print(f"Whirlpool: Generated {result}, Expected {hash_part}")
        return result == hash_part
    except Exception as e:
        print(f"Whirlpool error: {str(e)}")
        return False

def verify_md5(hash_part, plaintext):
    """Verify MD5 hash."""
    result = hashlib.md5(plaintext.encode()).hexdigest().lower()
    hash_part = hash_part.lower()
    print(f"MD5: Generated {result}, Expected {hash_part}")
    return result == hash_part

def verify_md5crypt(hash_part, plaintext):
    """Verify MD5crypt hash using passlib."""
    if not (hash_part.startswith("$1$") and len(hash_part.split('$')[-1]) == 22):
        print(f"MD5crypt: Malformed hash: {hash_part}")
        return False
    try:
        result = md5_crypt.verify(plaintext, hash_part)
        print(f"MD5crypt: Match={result}, Hash={hash_part}, Plaintext={plaintext}")
        return result
    except ValueError as e:
        print(f"MD5crypt error: {e}")
        return False

def verify_ntlm(lm_hash, nt_hash, plaintext):
    """Verify NTLM hash."""
    ntlm_hash = md4(plaintext.encode("utf-16le")).hexdigest().upper()
    print(f"NTLM: Generated {ntlm_hash}, Expected {nt_hash}")
    return ntlm_hash == nt_hash.upper()

def verify_pkzip(hash_part, plaintext):
    """Verify PKZIP hash format."""
    pkzip_pattern = r'\$pkzip\$\d+\*\d+\*\d+\*\d+\*[a-f0-9]+\*[a-f0-9]*\*[a-f0-9]+\*\d+\*[a-f0-9]+\*.*\$/pkzip\$'
    if not re.match(pkzip_pattern, hash_part):
        print(f"PKZIP: Invalid format: {hash_part}")
        return False
    print(f"PKZIP: Format validation passed for hash: {hash_part}")
    return True

def verify_pdf(hash_part, plaintext):
    """Verify PDF hash format."""
    pdf_pattern = r'\$pdf\$\d+\*\d+\*\d+\*-?\d+\*\d+\*\d+\*[a-f0-9]+\*\d+\*[a-f0-9]+\*\d+\*[a-f0-9]+'
    if not re.match(pdf_pattern, hash_part):
        print(f"PDF: Invalid format: {hash_part}")
        return False
    print(f"PDF: Format validation passed for hash: {hash_part}")
    return True

def verify_office(hash_part, plaintext):
    """Verify MS Office hash format."""
    office_pattern = r'\$office\$\*\d+\*\d+\*\d+\*[a-f0-9]+\*[a-f0-9]+\*[a-f0-9]+'
    if not re.match(office_pattern, hash_part):
        print(f"Office: Invalid format: {hash_part}")
        return False
    print(f"Office: Format validation passed for hash: {hash_part}")
    return True

def verify_hash_128(hash_part, plaintext):
    """Verify 128-character hashes (Whirlpool or SHA512)."""
    try:
        # Try Whirlpool first
        whirlpool_result = verify_whirlpool(hash_part, plaintext)
        if whirlpool_result:
            print("Hash type identified: Whirlpool")
            return True
            
        # Try SHA512 if Whirlpool didn't match
        sha512_result = verify_sha512(hash_part, plaintext)
        if sha512_result:
            print("Hash type identified: SHA512")
            return True
            
        return False
        
    except Exception as e:
        print(f"Hash verification error: {str(e)}")
        return False

def verify_potfile(potfile_path):
    if not os.path.isfile(potfile_path):
        print(f"Error: Potfile '{potfile_path}' does not exist.")
        return

    print(f"Verifying potfile: {potfile_path}\n")
    valid_entries = []
    invalid_entries = []

    with open(potfile_path, "r") as potfile:
        for line in potfile:
            try:
                line = line.strip()
                if ":" not in line:
                    raise ValueError("Invalid line format")

                # Handle NTLM hashes (LM:NT:plaintext)
                if line.count(":") == 2 and not any(x in line for x in ['$pkzip$', '$pdf$', '$office$']):
                    lm_hash, nt_hash, plaintext = line.split(":")
                    if verify_ntlm(lm_hash, nt_hash, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                    continue

                # Split hash and plaintext
                hash_part, plaintext = line.split(":", 1)

                # Check special formats first
                if hash_part.startswith("$pkzip$"):
                    if verify_pkzip(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                elif hash_part.startswith("$pdf$"):
                    if verify_pdf(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                elif hash_part.startswith("$office$"):
                    if verify_office(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                # Standard hash formats
                elif len(hash_part) == 32:  # MD5 or MD4
                    if verify_md5(hash_part, plaintext) or verify_md4(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                elif len(hash_part) == 40:  # SHA1
                    if verify_sha1(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                elif len(hash_part) == 64:  # SHA256
                    if verify_sha256(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                elif len(hash_part) == 128:  # Whirlpool or SHA512
                    if verify_hash_128(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                elif hash_part.startswith("$1$"):  # MD5crypt
                    if verify_md5crypt(hash_part, plaintext):
                        valid_entries.append(line)
                    else:
                        invalid_entries.append(line)
                else:
                    print(f"Unsupported hash format: {line}")
                    invalid_entries.append(line)
            except Exception as e:
                print(f"Error processing line: {line}, Error: {str(e)}")
                invalid_entries.append(line)

    print("\n### VALID ENTRIES ###")
    if valid_entries:
        for entry in valid_entries:
            print(entry)
    else:
        print("No valid entries found.")

    print("\n### INVALID ENTRIES ###")
    if invalid_entries:
        for entry in invalid_entries:
            print(entry)
    else:
        print("No invalid entries found.")

    print("\nSummary:")
    print(f"Valid entries: {len(valid_entries)}")
    print(f"Invalid entries: {len(invalid_entries)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: verify_potfile <potfile_path>")
        sys.exit(1)

    potfile_path = sys.argv[1]
    verify_potfile(potfile_path)

if __name__ == "__main__":
    main()
