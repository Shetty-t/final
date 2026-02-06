import psutil
import os
import shutil
import socket
import threading
import subprocess
import re
from scanner_engine import ScannerEngine

class SystemScanner:
    def __init__(self):
        self.engine = ScannerEngine()

    # -------------------------
    # MEMORY (RAM/KERNEL) SCAN
    # -------------------------
    def scan_memory(self, callback=None):
        """ Scans all running processes (backing executable files). """
        threats = []
        count = 0
        
        # Iterate over all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe_path = proc.info.get('exe')
                if exe_path and os.path.exists(exe_path):
                    status, conf, color = self.engine.scan_file(exe_path)
                    count += 1
                    
                    if status == "UNSAFE":
                        threats.append({
                            "type": "Process (RAM)",
                            "path": exe_path,
                            "pid": proc.info['pid'],
                            "conf": conf
                        })
                    
                    if callback:
                        callback(f"Scanning RAM: {proc.info['name']}...", count)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return threats

    # -------------------------
    # USB / DRIVE SCAN
    # -------------------------
    def get_usb_drives(self):
        usb_drives = []
        for part in psutil.disk_partitions():
            if 'removable' in part.opts or 'cdrom' in part.opts:
                usb_drives.append(part.mountpoint)
        return usb_drives

    def scan_usb(self, callback=None):
        drives = self.get_usb_drives()
        if not drives:
            return [], "No USB Drives Found"
            
        threats = []
        total_files = 0
        
        for drive in drives:
            if callback: callback(f"Scanning USB: {drive}", 0)
            
            for root, _, files in os.walk(drive):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        status, conf, color = self.engine.scan_file(path)
                        total_files += 1
                        
                        if status == "UNSAFE":
                            threats.append({
                                "type": "USB File",
                                "path": path,
                                "conf": conf
                            })
                    except: pass
                    
                    if total_files % 50 == 0 and callback:
                        callback(f"Scanning USB... ({total_files} checked)", total_files)
                        
        return threats, f"Scanned {total_files} files on USB."

    # -------------------------
    # NETWORK SCAN
    # -------------------------
    def scan_network_arp(self):
        """ Scans local network using ARP table (Fast/Safe). """
        devices = []
        try:
            # Run 'arp -a' to see cached devices
            output = subprocess.check_output("arp -a", shell=True).decode()
            
            # Regex to find IPs (Simple version)
            ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
            
            # Simple unique filter excluding loopback/multicast
            seen = set()
            for ip in ips:
                if ip not in seen and not ip.startswith("224.") and not ip.startswith("239.") and ip != "255.255.255.255":
                    seen.add(ip)
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "Unknown Device"
                    
                    devices.append({"ip": ip, "hostname": hostname, "status": "Online"})
                    
        except Exception as e:
            return [{"ip": "Error", "hostname": str(e), "status": "Failed"}]
            
        return devices
