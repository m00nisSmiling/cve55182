import json
import subprocess
import sys
import os
import time
os.system("docker ps --format '{{.Names}}' > ./ids")
# --- Vulnerable versions ---
time.sleep(3)
VULN_REACT = ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]

# Exact Next.js vulnerable ranges (user-provided)
VULN_NEXT_RANGES = [
    ("15.0.0", "15.0.4"),
    ("15.1.0", "15.1.8"),
    ("15.2.0", "15.2.5"),
    ("15.3.0", "15.3.5"),
    ("15.4.0", "15.4.7"),
    ("15.5.0", "15.5.6"),
    ("16.0.0", "16.0.6"),
]

# ---- Version comparison using ONLY default Python ----

def parse_ver(v):
    return tuple(int(x) for x in v.split("."))

def version_in_range(ver, start, end):
    v = parse_ver(ver)
    return parse_ver(start) <= v <= parse_ver(end)

# ---- Docker helpers ----

def run_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError:
        return None

def get_package_version(container, pkg):
    output = run_cmd(["docker", "exec", container, "npm", "list", pkg, "--json"])
    if not output:
        return None

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None

    deps = data.get("dependencies", {})
    if pkg in deps:
        return deps[pkg].get("version")
    return None

def is_next_vulnerable(ver):
    if not ver:
        return False
    for start, end in VULN_NEXT_RANGES:
        if version_in_range(ver, start, end):
            return True
    return False

# ---- Main logic ----

def check_container(container):
    print(f"\n====== {container} ======")

    react_v = get_package_version(container, "react")
    next_v = get_package_version(container, "next")

    if react_v is None and next_v is None:
        #print("[ERROR] Cannot run npm inside this container.")
        return

   # print(f"React version: {react_v}")
   # print(f"Next.js version: {next_v}")
   # print("--- Vulnerability Report ---")

    # React check
    if react_v in VULN_REACT:
        print(f"[!] React {react_v} -> VULNERABLE ")
    else:
        print(f"[OK] React {react_v} -> SECURE")

    # Next.js check
    if next_v and is_next_vulnerable(next_v):
        print(f"[!] Next.js {next_v} -> VULNERABLE")
    else:
        print(f"[OK] Next.js {next_v} -> SECURE")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <container_list_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path, "r") as f:
            containers = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        print("ERROR: File not found:", file_path)
        sys.exit(1)

    for container in containers:
        check_container(container)

    print("\n=== All containers scanned ===\n")

if __name__ == "__main__":
    main()
