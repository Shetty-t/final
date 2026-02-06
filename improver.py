import os
import joblib
import numpy as np
from scanner_engine import ScannerEngine
from sklearn.ensemble import RandomForestClassifier

# Reuse the engine's feature extractor
engine = ScannerEngine()

def auto_improve_brain():
    print("🧠 UPGRADING AI BRAIN (Unsupervised Learning)...")
    print("   Target: Learning 'Safe System Files' from Windows...")

    X = []
    y = []

    # 1. Load Existing Data first (to keep knowledge of malware)
    # We cheat a bit and re-extract from the dataset folder
    print("[1/3] Reloading original dataset...")
    base = os.path.dirname(os.path.abspath(__file__))
    benign_dir = os.path.join(base, "dataset", "benign")
    malware_dir = os.path.join(base, "dataset", "malware")

    if os.path.exists(benign_dir):
        for f in os.listdir(benign_dir):
            try:
                with open(os.path.join(benign_dir, f), "rb") as file:
                    X.append(engine.extract_features(file.read()).flatten())
                    y.append(0) # Safe
            except: pass

    if os.path.exists(malware_dir):
        for f in os.listdir(malware_dir):
            try:
                with open(os.path.join(malware_dir, f), "rb") as file:
                    X.append(engine.extract_features(file.read()).flatten())
                    y.append(1) # Malware
            except: pass

    # 2. Learn from Windows System32 (REAL Safe Files)
    print("[2/3] Learning from C:\\Windows\\System32 (Files are being processed)...")
    sys_dir = "C:\\Windows\\System32"
    count = 0
    max_files = 200 # Learn 200 system files (enough to generalize)

    try:
        for f in os.listdir(sys_dir):
            if count >= max_files: break
            if f.endswith(".dll") or f.endswith(".exe"):
                path = os.path.join(sys_dir, f)
                try:
                    # using the engine's shadow reader to avoid locks
                    # But for system32 we just try standard read
                    with open(path, "rb") as file:
                        data = file.read()
                        X.append(engine.extract_features(data).flatten())
                        y.append(0) # These are SAFE
                        count += 1
                except:
                    pass
    except Exception as e:
        print(f"⚠️ Warning: Could not access System32 ({e}). Try running as Admin.")

    print(f"   Collected {count} new Safe patterns.")

    # 3. Re-Train
    print(f"[3/3] Re-training Model with {len(X)} total samples...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)

    joblib.dump(clf, "scanner_model.pkl")
    print("\n✅ SUCCESS! The AI is now smarter.")
    print("   It now knows that System Files are SAFE.")
    print("   Restart the Antivirus App to see the changes.")

if __name__ == "__main__":
    auto_improve_brain()
