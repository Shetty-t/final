import os
import numpy as np
import pickle
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ----------------------------
# CONFIG
# ----------------------------
BASE = os.path.dirname(os.path.abspath(__file__))
BENIGN_DIR = os.path.join(BASE, "dataset", "benign")
MALWARE_DIR = os.path.join(BASE, "dataset", "malware")
MODEL_PATH = os.path.join(BASE, "scanner_model.pkl")

# ----------------------------
# FEATURE EXTRACTOR (THE "PROPERTIES" DNA)
# ----------------------------
def extract_features(data):
    if not data:
        return np.zeros(19) # 16 bins + 3 stats

    arr = np.frombuffer(data, dtype=np.uint8)
    size = len(data)

    # 1. Byte Histogram (16 bins, normalized)
    # We bin 0-255 into 16 groups (0-15, 16-31...) to see "byte distribution"
    hist, _ = np.histogram(arr, bins=16, range=(0, 256), density=True)
    
    # 2. Entropy (Randomness)
    probs = np.bincount(arr, minlength=256) / size
    entropy = -np.sum(probs[probs > 0] * np.log2(probs[probs > 0]))

    # 3. Structural Ratios
    printable = np.sum((arr >= 32) & (arr <= 126)) / size
    # logical size usually better than raw size
    log_size = np.log1p(size)

    # Combine all features: 16 hist values + entropy + printable + log_size
    return np.concatenate([hist, [entropy, printable, log_size]])

# ----------------------------
# DATA LOADER
# ----------------------------
def load_data():
    X, y = [], []
    
    # Load Benign (Label 0)
    print(f"[*] Loading BENIGN from {BENIGN_DIR}...")
    if os.path.exists(BENIGN_DIR):
        for f in os.listdir(BENIGN_DIR):
            try:
                with open(os.path.join(BENIGN_DIR, f), "rb") as file:
                    feat = extract_features(file.read())
                    X.append(feat)
                    y.append(0) # 0 = SAFE
            except Exception as e:
                pass

    # Load Malware (Label 1)
    print(f"[*] Loading MALWARE from {MALWARE_DIR}...")
    if os.path.exists(MALWARE_DIR):
        for f in os.listdir(MALWARE_DIR):
            try:
                with open(os.path.join(MALWARE_DIR, f), "rb") as file:
                    feat = extract_features(file.read())
                    X.append(feat)
                    y.append(1) # 1 = MALWARE
            except:
                pass
                
    return np.array(X), np.array(y)

# ----------------------------
# TRAIN
# ----------------------------
if __name__ == "__main__":
    print("--- AI TRAINING STARTED ---")
    X, y = load_data()

    if len(X) == 0:
        print("❌ ERROR: No data found in 'dataset/benign' or 'dataset/malware'.")
        print("   Please add files to train the model.")
        exit()

    print(f"[+] Total Samples: {len(X)}")
    
    # Train
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    # Evaluate (Self-Check)
    y_pred = clf.predict(X)
    acc = accuracy_score(y, y_pred)
    print(f"\n[+] Training Accuracy: {acc * 100:.2f}%")
    
    # Save
    joblib.dump(clf, MODEL_PATH)
    print(f"\n[✅] Model saved to: {MODEL_PATH}")
    print("    You can now run 'scanner_v3.py'!")
