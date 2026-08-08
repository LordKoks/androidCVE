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

# 3. Use Python to extract boot.img from payload.bin
echo "[*] Extracting boot.img using Python (Termux friendly)..."

# Install dependencies for the python dumper
pip install protobuf six

cat << 'EOF' > dumper.py
import struct
import os
import sys

def parse_payload(payload_file, out_dir):
    with open(payload_file, 'rb') as f:
        magic = f.read(4)
        if magic != b'CrAU':
            print("[!] Not a valid payload.bin")
            return
        
        file_format_version = struct.unpack('>Q', f.read(8))[0]
        manifest_len = struct.unpack('>Q', f.read(8))[0]
        
        metadata_signature_len = 0
        if file_format_version > 1:
            metadata_signature_len = struct.unpack('>I', f.read(4))[0]
            
        manifest_data = f.read(manifest_len)
        
        # We try to find the boot partition by manual searching in manifest
        # because installing full protobuf definitions is complex in a shell script
        # The manifest is a protobuf. We look for the string "boot"
        pos = manifest_data.find(b'\n\x04boot')
        if pos == -1:
            print("[!] Could not find 'boot' partition in manifest")
            return
            
        print("[+] Found 'boot' partition metadata in manifest")
        
        # Now we need the data offset. In payload.bin v2, data starts after:
        # magic(4) + version(8) + manifest_len(8) + metadata_sig_len(4) + manifest(manifest_len) + metadata_sig(metadata_sig_len)
        data_offset = 4 + 8 + 8 + 4 + manifest_len + metadata_signature_len
        
        # A very simplified approach: find the first large chunk of data 
        # that looks like a boot image (Android magic 'ANDROID!')
        f.seek(data_offset)
        print(f"[*] Scanning for Android Boot Magic from offset {data_offset}...")
        
        # We read in chunks to find 'ANDROID!'
        chunk_size = 1024 * 1024
        found = False
        while True:
            current_pos = f.tell()
            chunk = f.read(chunk_size)
            if not chunk: break
            
            magic_pos = chunk.find(b'ANDROID!')
            if magic_pos != -1:
                boot_start = current_pos + magic_pos
                print(f"[+] Found Android Boot Magic at offset {boot_start}")
                
                # Extract 128MB (usually enough for boot.img) or until next magic
                f.seek(boot_start)
                boot_data = f.read(128 * 1024 * 1024) 
                
                with open(os.path.join(out_dir, 'boot.img'), 'wb') as out:
                    out.write(boot_data)
                print("[+] boot.img extracted successfully!")
                found = True
                break
        
        if not found:
            print("[!] Failed to find boot image magic in data area.")

if __name__ == '__main__':
    parse_payload('payload.bin', '.')
EOF

python3 dumper.py

if [ ! -f boot.img ]; then
    echo "[!] Error: Failed to extract boot.img using Python."
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
