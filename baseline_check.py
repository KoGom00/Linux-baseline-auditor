import json, os, socket
from datetime import datetime, timezone

FILE_BASELINES = {
    "/etc/passwd": "644",
    "/etc/shadow": "640",
    "test_secret.conf": "600",
}
SSH_CONFIG = "/etc/ssh/sshd_config"

def check_permissions(filepath, expected_perm):
    if not os.path.exists(filepath):
        return {"target": filepath, "status": "ERROR", "detail": "File not found"}
    actual_perm = oct(os.stat(filepath).st_mode)[-3:]
    status = "PASS" if actual_perm == expected_perm else "FAIL - Drift Detected"
    return {"target": filepath, "expected": expected_perm, "actual": actual_perm, "status": status}

def check_ssh_root_login(filepath):
    if not os.path.exists(filepath):
        return {"target": filepath, "status": "SKIPPED", "detail": "SSH config not found"}
    with open(filepath, "r") as f:
        for line in f:
            clean = line.strip()
            if clean.startswith("PermitRootLogin") and not clean.startswith("#"):
                setting = clean.split()[1]
                status = "PASS" if setting.lower() == "no" else "FAIL - Drift Detected"
                return {"target": "PermitRootLogin", "expected": "no", "actual": setting, "status": status}
    return {"target": "PermitRootLogin", "expected": "no", "actual": "unset", "status": "FAIL - Drift Detected"}

def main():
    results = [check_permissions(path, perm) for path, perm in FILE_BASELINES.items()]
    results.append(check_ssh_root_login(SSH_CONFIG))
    evidence = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "hostname": socket.gethostname(), "checks": results}
    with open("compliance_evidence.json", "w") as out_file:
        json.dump(evidence, out_file, indent=4)
    print("Audit complete. Evidence saved to compliance_evidence.json")

if __name__ == "__main__":
    main()
