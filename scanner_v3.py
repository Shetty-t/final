import os
import hashlib
import numpy as np
import pandas as pd
import shutil
import tempfile

# ----------------------------
# PATH SETUP
# ----------------------------
import joblib

# ----------------------------
# CONFIG
# ----------------------------
BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "scanner_model.pkl")
MALWARE_CSV = os.path.join(BASE, "Malware dataset.csv")

# ----------------------------
# FEATURE EXTRACTION (MUST MATCH TRAIN_MODEL.PY)
# ----------------------------
def extract_features(data):
    if not data:
        return np.zeros(19)

    arr = np.frombuffer(data, dtype=np.uint8)
    size = len(data)

    # 1. Byte Histogram (16 bins, normalized)
    hist, _ = np.histogram(arr, bins=16, range=(0, 256), density=True)
    
    # 2. Entropy
    probs = np.bincount(arr, minlength=256) / size
    entropy = -np.sum(probs[probs > 0] * np.log2(probs[probs > 0]))

    # 3. Structural Ratios
    printable = np.sum((arr >= 32) & (arr <= 126)) / size
    log_size = np.log1p(size)

    return np.concatenate([hist, [entropy, printable, log_size]]).reshape(1, -1)

# ----------------------------
# LOAD AI MODEL
# ----------------------------
print("[*] Loading AI Brain (Random Forest)...")
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("[+] AI Model loaded successfully.")
    except Exception as e:
        print(f"[!] Error loading model: {e}")
else:
    print("[!] Model not found. Running in fallback mode (Hash only).")
    print("    PLEASE RUN 'train_model.py' TO ENABLE AI SCANNING.")

# ----------------------------
# LOAD MALWARE HASHES
# ----------------------------
malware_hashes = set()
if os.path.exists(MALWARE_CSV):
    try:
        df = pd.read_csv(MALWARE_CSV)
        if "hash" in df.columns:
            malware_hashes = set(df["hash"].astype(str))
    except:
        pass

# ----------------------------
# AI DECISION ENGINE
# ----------------------------
def classify_ai(features):
    if model is None:
        return "UNKNOWN (No Model)"
    
    # Predict Probability
    # Class 0 = Safe, Class 1 = Malware
    probs = model.predict_proba(features)[0]
    malware_prob = probs[1]
    
    confidence = malware_prob * 100
    if malware_prob > 0.5:
        return f"UNSAFE ({confidence:.1f}%)"
    else:
        return f"SAFE ({100 - confidence:.1f}%)"

# ----------------------------
# SHADOW COPY READ
# ----------------------------
def read_file_shadow(path):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        
        shutil.copy2(path, tmp_path)

        with open(tmp_path, "rb") as f:
            data = f.read()

        return data

    except Exception:
        return None
        
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass

# ----------------------------
# SCAN FILE
# ----------------------------
def scan_file(path):
    data = read_file_shadow(path)
    if data is None:
        return

    # 1. Exact Hash Match (Instant)
    md5 = hashlib.md5(data).hexdigest()
    if md5 in malware_hashes:
        print(f"[❌ UNSAFE | HASH MATCH] {path}")
        return

    # 2. AI Analysis
    features = extract_features(data)
    result = classify_ai(features)

    # Display
    color_icon = "✅" if result.startswith("SAFE") else "❌"
    print(f"[{color_icon} {result}] {path}")

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    target = input("Enter FILE or FOLDER path to scan: ").strip().strip('"')

    if os.path.isfile(target):
        scan_file(target)

    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            for f in files:
                scan_file(os.path.join(root, f))
    else:
        print("❌ Invalid path")
