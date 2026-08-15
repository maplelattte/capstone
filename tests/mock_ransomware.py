import os
import time

SANDBOX_DIR = "/tmp/ransom_test_sandbox"

def simulate_ransomware():
    print(f"[*] Starting controlled simulation on PID: {os.getpid()}")
    print(f"[*] Target directory: {SANDBOX_DIR}")

    if not os.path.exists(SANDBOX_DIR):
        print("[-] Sandbox directory does not exist! Run Step 1 first.")
        return

    files = [f for f in os.listdir(SANDBOX_DIR) if f.endswith(".txt")]
    print(f"[*] Found {len(files)} target files to encrypt.")

    for filename in sorted(files):
        filepath = os.path.join(SANDBOX_DIR, filename)

        # 1. Overwrite file with high-entropy pseudo-random bytes
        random_payload = os.urandom(512)
        with open(filepath, "wb") as f:
            f.write(random_payload)

        # 2. Simulate extension churn / rename
        new_filepath = filepath + ".locked"
        os.rename(filepath, new_filepath)

        print(f"  -> Encrypted & renamed: {filename} -> {filename}.locked")
        time.sleep(0.01) # Rapid I/O pace

    print("[!] Simulation finished (if you see this, threshold was not triggered).")

if __name__ == "__main__":
    simulate_ransomware()
