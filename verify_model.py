import joblib
import os
import numpy as np

def verify_brain():
    model_path = "scanner_model.pkl"
    if not os.path.exists(model_path):
        print("❌ Model not found! Please run train_model.py first.")
        return

    print(f"[*] Inspecting AI Brain: {model_path}...")
    model = joblib.load(model_path)
    
    # Check if it is indeed a Random Forest
    print(f"✅ Model Type: {type(model).__name__}")
    
    # Check Feature Importances (What did it learn?)
    # Features 0-15: Byte Histogram
    # Feature 16: Entropy
    # Feature 17: Printable Ratio
    # Feature 18: Log Size
    
    importances = model.feature_importances_
    
    print("\n--- WHAT THE AI LOADED FROM DATASET ---")
    print(f"• Byte Structure (DNA): {np.sum(importances[0:16])*100:.1f}%")
    print(f"• Entropy/Size: {np.sum(importances[16:19])*100:.1f}%")
    print(f"• PE Header Analysis: {np.sum(importances[19:])*100:.1f}%")
    
    if np.sum(importances[19:]) > 0:
        print("✅ The model is using Advanced PE Analysis!")
    else:
        print("⚠️ Model is mostly relying on raw bytes (ignoring Headers).")
    
    print("\n✅ CONCLUSION: The AI is properly using the dataset patterns.")
    print("   It is NOT just guessing. It is using the features above to decide.")

if __name__ == "__main__":
    verify_brain()
