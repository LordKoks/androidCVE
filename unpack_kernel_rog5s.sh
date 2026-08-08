#!/bin/bash

# Script to unpack and disassemble ASUS ROG 5S Kernel from firmware ZIP
# Author: Trae AI Assistant

ZIP_FILE="UL-ASUS_I005_1-ASUS-33.0210.0210.200-1.1.300-2304-user.zip"
OUT_DIR="kernel_unpack"

echo "[*] Starting kernel extraction process..."

# 1. Check if ZIP exists
if [ ! -f "$ZIP_FILE" ]; then
    echo "[!] Error: $ZIP_FILE not found in current directory."
    exit 1
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# 2. Extract payload.bin from ZIP
echo "[*] Extracting payload.bin from ZIP..."
unzip -p "../$ZIP_FILE" payload.bin > payload.bin

if [ ! -s payload.bin ]; then
    echo "[!] Error: Failed to extract payload.bin or it is empty."
    exit 1
fi

# 3. Download payload-dumper-go
echo "[*] Downloading payload-dumper-go..."
ARCH=$(uname -m)
if [ "$ARCH" == "aarch64" ]; then
    DUMPER_URL="https://github.com/ssut/payload-dumper-go/releases/download/1.2.2/payload-dumper-go_1.2.2_linux_arm64.tar.gz"
else
    DUMPER_URL="https://github.com/ssut/payload-dumper-go/releases/download/1.2.2/payload-dumper-go_1.2.2_linux_amd64.tar.gz"
fi

curl -L "$DUMPER_URL" -o dumper.tar.gz
tar -xzf dumper.tar.gz
chmod +x payload-dumper-go

# 4. Extract boot partition
echo "[*] Extracting boot.img from payload.bin..."
./payload-dumper-go -p boot payload.bin

# Move boot.img to current dir
mv extracted_*/boot.img .

if [ ! -f boot.img ]; then
    echo "[!] Error: Failed to extract boot.img."
    exit 1
fi

# 5. Download magiskboot for unpacking boot.img
echo "[*] Downloading magiskboot..."
# Using a known stable source for magiskboot binary
if [ "$ARCH" == "aarch64" ]; then
    MAGISK_URL="https://github.com/User706/magiskboot-binaries/raw/master/aarch64/magiskboot"
else
    MAGISK_URL="https://github.com/User706/magiskboot-binaries/raw/master/x86_64/magiskboot"
fi

curl -L "$MAGISK_URL" -o magiskboot
chmod +x magiskboot

# 6. Unpack boot.img
echo "[*] Unpacking boot.img..."
./magiskboot unpack boot.img

if [ ! -f kernel ]; then
    echo "[!] Error: Failed to unpack kernel from boot.img."
    exit 1
fi

# 7. Decompress kernel if needed
echo "[*] Processing kernel image..."
if grep -q "gzip compressed" <(file kernel); then
    echo "[*] Decompressing gzip kernel..."
    mv kernel kernel.gz
    gunzip kernel.gz
elif grep -q "LZ4 compressed" <(file kernel); then
    echo "[*] Decompressing LZ4 kernel..."
    lz4 -d kernel kernel.unpacked
    mv kernel.unpacked kernel
fi

FILE_TYPE=$(file kernel)
echo "[*] Final kernel file type: $FILE_TYPE"

# 8. Extract kernel information (Version, Config)
echo "[*] Extracting kernel info..."
strings kernel | grep "Linux version" | head -n 1 > kernel_version.txt
echo "[+] Kernel Version: $(cat kernel_version.txt)"

# Try to extract ikconfig
echo "[*] Attempting to extract ikconfig..."
# We can use a python script for this
cat << 'EOF' > extract_config.py
import sys
import gzip

def find_config(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        
    # Look for ikconfig magic
    magic = b'IKCFG_ST'
    pos = data.find(magic)
    if pos == -1:
        return None
    
    # Found it, now find the end or just try to decompress from there
    # The config is usually gzipped
    start = pos + 8
    try:
        # Search for gzip magic near the start
        gz_pos = data.find(b'\x1f\x8b\x08', start, start + 100)
        if gz_pos != -1:
            config_data = gzip.decompress(data[gz_pos:])
            return config_data
    except:
        pass
    return None

conf = find_config('kernel')
if conf:
    with open('kernel_config.txt', 'wb') as f:
        f.write(conf)
    print("[+] Successfully extracted kernel config to kernel_config.txt")
else:
    print("[-] Could not find embedded ikconfig in kernel.")
EOF

python3 extract_config.py

# 9. Disassemble a small part for verification (requires objdump)
if command -v objdump >/dev/null 2>&1; then
    echo "[*] Disassembling first 100 instructions..."
    objdump -D -b binary -m aarch64 kernel | head -n 100 > kernel_disasm_head.txt
fi

echo ""
echo "[+++] DONE! Extracted files are in $OUT_DIR/"
ls -lh kernel kernel_version.txt kernel_config.txt 2>/dev/null

echo ""
echo "[*] Next steps for offset finding:"
echo "1. Use 'grep' on 'kernel' to find interesting strings."
echo "2. Use 'nm' or 'objdump' if you have a vmlinux (uncompressed kernel)."
echo "3. Use 'kallsyms_dumper' on the live device if possible."
