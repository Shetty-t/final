import os
import shutil
import hashlib
import numpy as np
import joblib
import tempfile
import threading
import time
import pandas as pd
import pefile

class ScannerEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_dir, "scanner_model.pkl")
        self.quarantine_dir = os.path.join(self.base_dir, "quarantine")
        self.malware_csv = os.path.join(self.base_dir, "Malware dataset.csv")
        
        # Create Quarantine Dirs
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

        self.model = self._load_model()
        self.hashes = self._load_hashes()

    def _load_model(self):
        try:
            if os.path.exists(self.model_path):
                return joblib.load(self.model_path)
        except:
            pass
        return None

    def _load_hashes(self):
        hashes = set()
        if os.path.exists(self.malware_csv):
            try:
                df = pd.read_csv(self.malware_csv)
                if "hash" in df.columns:
                    hashes = set(df["hash"].astype(str))
            except:
                pass
        return hashes

    def extract_pe_features(self, data):
        """ Extract 8 solid features from PE Header """
        try:
            pe = pefile.PE(data=data)
            
            # 1. Number of Sections (Malware often has weird counts)
            num_sections = len(pe.sections)
            
            # 2. Entropy of Text Section (Code)
            text_entropy = 0.0
            for section in pe.sections:
                if b".text" in section.Name:
                    text_entropy = section.get_entropy()
                    break
            
            # 3. Import Count
            try: num_imports = len(pe.DIRECTORY_ENTRY_IMPORT)
            except: num_imports = 0

            # 4. Export Count
            try: num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            except: num_exports = 0
            
            # 5. Has Debug Info?
            has_debug = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
            
            # 6. Has Relocations?
            has_reloc = 1 if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else 0
            
            # 7. Has Resources?
            has_rsrc = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
            
            # 8. Entry Point (Address)
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            return [num_sections, text_entropy, num_imports, num_exports, has_debug, has_reloc, has_rsrc, entry_point]

        except:
            # Corrupt PE or parse error
            return [0] * 8

    def extract_features(self, data):
        # Base Features (19)
        if not data: return np.zeros(27) # 19 + 8

        arr = np.frombuffer(data, dtype=np.uint8)
        size = len(data)
        
        # 1. Byte Histogram (16 bins)
        hist, _ = np.histogram(arr, bins=16, range=(0, 256), density=True)
        # 2. Entropy
        probs = np.bincount(arr, minlength=256) / size
        entropy = -np.sum(probs[probs > 0] * np.log2(probs[probs > 0]))
        # 3. Structure
        printable = np.sum((arr >= 32) & (arr <= 126)) / size
        log_size = np.log1p(size)
        
        base_feats = np.concatenate([hist, [entropy, printable, log_size]])

        # PE Features (8) - Hybrid Approach
        # Check for MZ header
        if data.startswith(b'MZ'):
            pe_feats = self.extract_pe_features(data)
        else:
            pe_feats = [0] * 8
            
        return np.concatenate([base_feats, pe_feats]).reshape(1, -1)

    def scan_file(self, path):
        """ Returns: (status, confidence_str, color) """
        tmp_path = None
        try:
            # Shadow Copy Read
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name
            shutil.copy2(path, tmp_path)
            
            with open(tmp_path, "rb") as f:
                data = f.read()

            # Hash Check
            md5 = hashlib.md5(data).hexdigest()
            if md5 in self.hashes:
                return "UNSAFE", "100% (Hash)", "red"

            # AI Check
            if self.model:
                feats = self.extract_features(data)
                probs = self.model.predict_proba(feats)[0]
                conf = probs[1] * 100
                if probs[1] > 0.5:
                    return "UNSAFE", f"{conf:.1f}%", "red"
                else:
                    return "SAFE", f"{100-conf:.1f}%", "green"
            else:
                return "Unknown", "No Model", "gray"

        except Exception as e:
            return "Error", str(e), "yellow"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try: os.remove(tmp_path) 
                except: pass

    def quarantine_file(self, path):
        try:
            fname = os.path.basename(path)
            dest = os.path.join(self.quarantine_dir, fname + ".quarantined")
            shutil.move(path, dest)
            return True, dest
        except Exception as e:
            return False, str(e)

    def delete_file(self, path):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            return True, "Deleted"
        except Exception as e:
            return False, str(e)
