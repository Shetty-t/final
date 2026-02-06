from scanner_engine import ScannerEngine
import os
import shutil

def test_engine():
    print("Testing ScannerEngine...")
    engine = ScannerEngine()
    
    # 1. Test Scanning
    print("\n[Test 1] Scanning 'dataset/malware'...")
    malware_path = os.path.join("dataset", "malware", "suspicious_script.jse")
    # If .jse doesn't exist, pick any file in malware dir
    if not os.path.exists(malware_path):
        m_files = os.listdir(os.path.join("dataset", "malware"))
        if m_files:
            malware_path = os.path.join("dataset", "malware", m_files[0])
    
    if os.path.exists(malware_path):
        status, conf, color = engine.scan_file(malware_path)
        print(f"Result: {status} ({conf})")
        assert status == "UNSAFE", "Failed to detect malware!"
    else:
        print("Skipping Malware Test (No files)")

    # 2. Test Quarantine
    print("\n[Test 2] Testing Quarantine...")
    # Create a dummy file
    dummy = "test_virus.tmp"
    with open(dummy, "w") as f: f.write("malicious code simulation")
    
    success, dest = engine.quarantine_file(dummy)
    if success:
        print(f"Quarantined to: {dest}")
        if os.path.exists(dest) and not os.path.exists(dummy):
            print("✅ Quarantine Successful")
        else:
            print("❌ Quarantine Failed (File check)")
    else:
        print(f"❌ Quarantine Error: {dest}")

if __name__ == "__main__":
    test_engine()
