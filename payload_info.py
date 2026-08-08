import urllib.request
import struct

# Simplified payload.bin header parser
def parse_payload_header(url):
    # Payload header is usually small
    req = urllib.request.Request(url, headers={'Range': 'bytes=0-4096'})
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            if data[:4] != b'CrAU':
                print("Not a valid payload.bin or header mismatch")
                return
            
            # Format: magic(4), version(8), manifest_len(8), metadata_signature_len(4)
            version, manifest_len, metadata_sig_len = struct.unpack('>QQL', data[4:24])
            print(f"Payload Version: {version}")
            print(f"Manifest Length: {manifest_len}")
            
            # Now we need to read the manifest (Protobuf encoded)
            # Manifest contains the partition info
            # We'd need a protobuf parser here, which might be overkill
            # But we can look for "boot" string in the manifest
            
            req_manifest = urllib.request.Request(url, headers={'Range': f'bytes=24-{24+manifest_len}'})
            with urllib.request.urlopen(req_manifest) as resp_m:
                manifest_data = resp_m.read()
                if b'boot' in manifest_data:
                    print("Found 'boot' partition in manifest!")
                else:
                    print("'boot' partition not found in first manifest chunk")
    except Exception as e:
        print(f"Error: {e}")

# Note: The URL in the prompt is for the ZIP. payload.bin is INSIDE the zip.
# To do this, we'd need to find the offset of payload.bin inside the zip first.
