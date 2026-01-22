import pickle
import pandas as pd
import os
import json
import hashlib
from pathlib import Path
import requests
try:
    import magic
except ImportError:
    magic = None

# Load the trained model and scaler
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

class MalwareScanner:
    def __init__(self):
        self.virustotal_api = None  # Optional: Add your VirusTotal API key here
        self.detection_methods = []
    
    def get_file_hash(self, filepath):
        """Calculate SHA256 and MD5 hashes"""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
                    md5.update(chunk)
            return {'SHA256': sha256.hexdigest(), 'MD5': md5.hexdigest()}
        except Exception as e:
            print(f"[!] Error calculating hash: {e}")
            return None
    
    def check_virustotal(self, file_hash):
        """Check file against VirusTotal (requires API key)"""
        if not self.virustotal_api:
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash['SHA256']}"
            headers = {"x-apikey": self.virustotal_api}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    'detections': stats['malicious'],
                    'total': sum(stats.values()),
                    'source': 'VirusTotal'
                }
        except:
            pass
        return None
    
    def analyze_memory_features(self, filepath):
        """Analyze using memory-based ML model"""
        try:
            ext = Path(filepath).suffix.lower()
            
            # Load data based on file format
            if ext == '.csv':
                data = pd.read_csv(filepath, encoding='utf-8')
            elif ext == '.json':
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = pd.DataFrame(json.load(f))
            elif ext in ['.xlsx', '.xls']:
                data = pd.read_excel(filepath)
            else:
                return None
            
            # Clean data
            if 'Category' in data.columns:
                data = data.drop('Category', axis=1)
            if 'Class' in data.columns:
                data = data.drop('Class', axis=1)
            
            # Get numeric columns only
            numeric_data = data.select_dtypes(include=['number'])
            
            if len(numeric_data.columns) == 0:
                return None
            
            # Predict
            data_scaled = scaler.transform(numeric_data)
            predictions = model.predict(data_scaled)
            probabilities = model.predict_proba(data_scaled)
            
            malware_count = sum(predictions == 1)
            malware_percent = (malware_count / len(predictions)) * 100
            avg_confidence = max([max(probs) for probs in probabilities]) * 100
            
            return {
                'method': 'Memory Analysis (ML)',
                'malware_detected': malware_count > 0,
                'confidence': avg_confidence,
                'malware_count': malware_count,
                'total_samples': len(predictions),
                'malware_percent': malware_percent
            }
        except:
            return None
    
    def analyze_file_signature(self, filepath):
        """Analyze file signatures and magic bytes"""
        try:
            suspicious_signatures = {
                b'MZ': 'Windows Executable',
                b'PK': 'ZIP Archive (Potentially Packed)',
                b'7z': '7z Archive',
                b'\xfd7zXZ': 'XZ Compressed',
                b'Rar!': 'RAR Archive',
                b'%PDF': 'PDF File',
                b'GIF8': 'GIF Image',
                b'\xff\xd8\xff': 'JPEG Image',
                b'\x89PNG': 'PNG Image'
            }
            
            with open(filepath, 'rb') as f:
                magic_bytes = f.read(16)
            
            detected_type = 'Unknown'
            for sig, file_type in suspicious_signatures.items():
                if magic_bytes.startswith(sig):
                    detected_type = file_type
                    break
            
            return {
                'method': 'Signature Analysis',
                'file_type': detected_type,
                'risk_score': 0.3 if 'Executable' in detected_type or 'Archive' in detected_type else 0.1
            }
        except:
            return None
    
    def scan_file(self, filepath):
        """Comprehensive malware scan"""
        try:
            # Normalize the filepath
            filepath = os.path.normpath(filepath)
            
            # Check if file exists
            if not os.path.exists(filepath):
                print(f"[!] Error: File '{filepath}' not found!")
                return
            
            print(f"\n{'='*80}")
            print(f"[*] COMPREHENSIVE MALWARE SCAN")
            print(f"{'='*80}")
            print(f"[*] File: {os.path.basename(filepath)}")
            print(f"[*] Path: {os.path.abspath(filepath)}")
            print(f"[*] Size: {os.path.getsize(filepath) / 1024:.2f} KB")
            
            # Get hashes
            hashes = self.get_file_hash(filepath)
            if not hashes:
                print("[!] Failed to calculate file hashes")
                return
            print(f"[*] SHA256: {hashes['SHA256']}")
            print(f"[*] MD5: {hashes['MD5']}")
            print(f"{'='*80}\n")
            
            results = {
                'filename': os.path.basename(filepath),
                'hashes': hashes,
                'analyses': [],
                'overall_verdict': 'UNKNOWN',
                'risk_score': 0
            }
            
            # Analysis 1: Signature Analysis
            print("[*] Running Signature Analysis...")
            sig_result = self.analyze_file_signature(filepath)
            if sig_result:
                results['analyses'].append(sig_result)
                print(f"    [+] File Type: {sig_result['file_type']}")
                print(f"    [+] Risk Score: {sig_result['risk_score']:.2f}\n")
            
            # Analysis 2: Memory-based ML Analysis
            print("[*] Running Memory-based ML Analysis...")
            mem_result = self.analyze_memory_features(filepath)
            if mem_result:
                results['analyses'].append(mem_result)
                status = "MALWARE DETECTED" if mem_result['malware_detected'] else "BENIGN"
                print(f"    [+] Status: {status}")
                print(f"    [+] Confidence: {mem_result['confidence']:.2f}%")
                print(f"    [+] Malware Samples: {mem_result['malware_count']}/{mem_result['total_samples']}\n")
            
            # Analysis 3: VirusTotal (if available)
            print("[*] Checking Online Databases...")
            vt_result = self.check_virustotal(hashes)
            if vt_result:
                results['analyses'].append(vt_result)
                print(f"    [+] VirusTotal Detections: {vt_result['detections']}/{vt_result['total']}\n")
            else:
                print("    [!] VirusTotal: Skipped (API key not configured)\n")
            
            # Calculate overall verdict
            print(f"{'='*80}")
            print("FINAL VERDICT:")
            print(f"{'='*80}\n")
            
            malware_indicators = 0
            total_indicators = len(results['analyses'])
            
            if sig_result and sig_result.get('risk_score', 0) > 0.2:
                malware_indicators += 1
            
            if mem_result and mem_result.get('malware_detected'):
                malware_indicators += 1
            
            if vt_result and vt_result.get('detections', 0) > 0:
                malware_indicators += 1
            
            risk_percentage = (malware_indicators / max(total_indicators, 1)) * 100
            results['risk_score'] = risk_percentage
            
            if risk_percentage >= 66:
                results['overall_verdict'] = 'LIKELY MALWARE'
                print(">>> VERDICT: LIKELY MALWARE <<<")
                print(f">>> Risk Score: {risk_percentage:.1f}% <<<")
                print("\n!!! TAKE IMMEDIATE ACTION - DO NOT EXECUTE !!!\n")
            elif risk_percentage >= 33:
                results['overall_verdict'] = 'SUSPICIOUS'
                print(">>> VERDICT: SUSPICIOUS <<<")
                print(f">>> Risk Score: {risk_percentage:.1f}% <<<")
                print("\n[!] Further analysis recommended\n")
            else:
                results['overall_verdict'] = 'LIKELY BENIGN'
                print(">>> VERDICT: LIKELY BENIGN <<<")
                print(f">>> Risk Score: {risk_percentage:.1f}% <<<")
                print("\n[OK] File appears safe\n")
            
            print(f"{'='*80}\n")
            
        except Exception as e:
            print(f"[!] Scan error: {e}\n")

def main():
    print("\n" + "="*80)
    print(" "*20 + "ADVANCED MALWARE DETECTION SYSTEM v3.0")
    print(" "*15 + "Multi-Engine Analysis: Signature + ML + Database")
    print("="*80 + "\n")
    
    scanner = MalwareScanner()
    
    while True:
        filepath = input("[*] Enter file path to scan (or 'quit' to exit): ").strip()
        
        if filepath.lower() == 'quit':
            print("\n[*] Exiting scanner. Goodbye!\n")
            break
        
        if filepath:
            scanner.scan_file(filepath)
        else:
            print("[!] Please enter a valid path.\n")

if __name__ == "__main__":
    main()
