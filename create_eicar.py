eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
with open("test_malware.com", "w") as f:
    f.write(eicar)
print("✅ EICAR test file created: test_malware.com")
print("💡 Your AI IPS/IDS should detect this!")
