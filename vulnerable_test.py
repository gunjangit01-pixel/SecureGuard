# Intentionally vulnerable test file for OSV scanning

import yaml  # PyYAML (older versions vulnerable)
import requests  # Some versions have known issues
import hashlib
import subprocess
import pickle

# 1. Unsafe YAML loading (RCE vulnerability)
def unsafe_yaml_load():
    data = """
    !!python/object/apply:os.system ["echo Vulnerable YAML Execution"]
    """
    yaml.load(data, Loader=yaml.Loader)  # ❌ unsafe

# 2. Hardcoded secret (bad practice)
API_KEY = "12345-SECRET-KEY"

# 3. Weak hashing algorithm
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # ❌ MD5 is insecure

# 4. Command injection vulnerability
def run_command(user_input):
    subprocess.call("echo " + user_input, shell=True)  # ❌ unsafe

# 5. Insecure deserialization
def insecure_pickle():
    data = pickle.dumps({"test": "data"})
    pickle.loads(data)  # ❌ unsafe

# 6. SSRF-like unsafe request
def unsafe_request(url):
    return requests.get(url)  # ❌ no validation

if __name__ == "__main__":
    unsafe_yaml_load()
    print(weak_hash("password"))
    run_command("Hello; rm -rf /")  # dangerous input
    insecure_pickle()
    unsafe_request("http://example.com")