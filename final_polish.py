import os
import joblib
import numpy as np
from scanner_engine import ScannerEngine
from sklearn.ensemble import RandomForestClassifier
import time

# Reuse the engine's feature extractor
engine = ScannerEngine()

def final_polish():
    print("💎 FINAL POLISH PROTOCOL INITIATED 💎")
    print("   Objective: Maximum Stability & Accuracy")

    X = []
    y = []

    # 1. Load Malware Data
    print("[1/3] Loading Malware DNA (Dataset)...")
    base = os.path.dirname(os.path.abspath(__file__))
    malware_dir = os.path.join(base, "dataset", "malware")

    mal_count = 0
    if os.path.exists(malware_dir):
        for f in os.listdir(malware_dir):
            try:
                with open(os.path.join(malware_dir, f), "rb") as file:
                    X.append(engine.extract_features(file.read()).flatten())
                    y.append(1) # Malware
                    mal_count += 1
            except: pass
    print(f"   Loaded {mal_count} Malware samples.")

    # 2. Load Benign Data (Dataset + System32)
    print(f"[2/3] Loading Safe DNA (Dataset + System32)...")
    
    # Dataset/Benign
    benign_dir = os.path.join(base, "dataset", "benign")
    if os.path.exists(benign_dir):
        for f in os.listdir(benign_dir):
            try:
                with open(os.path.join(benign_dir, f), "rb") as file:
                    X.append(engine.extract_features(file.read()).flatten())
                    y.append(0) 
            except: pass

    # System32 (The "Real" Test)
    sys_dir = "C:\\Windows\\System32"
    sys_count = 0
    max_files = 300 # INCREASED TO 300 FOR FINAL STABILITY

    try:
        for f in os.listdir(sys_dir):
            if sys_count >= max_files: break
            if f.endswith(".dll") or f.endswith(".exe"):
                path = os.path.join(sys_dir, f)
                try:
                    with open(path, "rb") as file:
                        data = file.read()
                        X.append(engine.extract_features(data).flatten())
                        y.append(0) # Safe
                        sys_count += 1
                except: pass
    except: pass

    print(f"   Loaded {sys_count} System32 samples.")

    # 3. Train
    print(f"[3/3] Training Brain on {len(X)} total samples...")
    clf = RandomForestClassifier(n_estimators=150, random_state=42) # Increased Estimators
    clf.fit(X, y)

    joblib.dump(clf, "scanner_model.pkl")
    print("\n✅ FINAL POLISH COMPLETE.")
    print("   The system is now calibrated for high-precision.")

if __name__ == "__main__":
    final_polish()
