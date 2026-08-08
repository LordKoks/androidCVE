import urllib.request
import zipfile
import io

url = 'https://dlcdnta.asus.com/pub/ASUS/ZenFone/ZS673KS/UL-ASUS_I005_1-ASUS-33.0210.0210.200-1.1.300-2304-user.zip?model=ROG%20Phone%205S%20(ZS676KS)&Signature=mv3xkW~7T6tv2UQHc5OFNt0iLvLwmc4IwzbEmpXGKKAztMSus2oHubTQ0hSDPR9H0LCUcy6HEjcfSRgd4zU-qKJ5Q7Yc0yrvC10ns~MWaNESov9jnyfpxbpHoiGASipmzc3I1D5IhUJW0mIj3F--8c4amA2FMbS2z2qeOHYMbUCwbzfiTpcBP1fKwOaC1bqDWNz4X-JewpTjQ4crwU83mDsJr6Y~ftz0B0hz4rK0vegniVvae1uw0pi9o-6atNIL5BI-bPqzPGP5GX0exvNDdEfGGyLEDoJdsp9hVs-xUZtLxGFzcFBHp0JoFs0bPiUcCd9W99xbs7ZGPAJY7tjStQ__&Expires=1786204585&Key-Pair-Id=K2ITB7O97XKKCX'

class RemoteZipFile(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        self.offset = 0
        req = urllib.request.Request(self.url, method='HEAD')
        with urllib.request.urlopen(req) as resp:
            self.size = int(resp.headers['Content-Length'])

    def read(self, size=-1):
        if size == -1: size = self.size - self.offset
        if self.offset >= self.size: return b''
        end = min(self.offset + size - 1, self.size - 1)
        req = urllib.request.Request(self.url, headers={'Range': f'bytes={self.offset}-{end}'})
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            self.offset += len(data)
            return data

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET: self.offset = offset
        elif whence == io.SEEK_CUR: self.offset += offset
        elif whence == io.SEEK_END: self.offset = self.size + offset
        return self.offset

    def tell(self): return self.offset

try:
    remote_file = RemoteZipFile(url)
    with zipfile.ZipFile(remote_file) as z:
        info = z.getinfo('payload.bin')
        # zipfile doesn't directly expose the byte offset of the file data
        # but we can get it from the internal header
        print(f"File: payload.bin")
        print(f"Compressed Size: {info.file_size}")
        print(f"Header Offset: {info.header_offset}")
except Exception as e:
    print(f"Error: {e}")
