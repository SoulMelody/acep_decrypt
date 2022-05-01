import argparse
import base64
import binascii
import hashlib
import json
import zstandard
from Crypto.Cipher import AES


def decrypt_ace_studio_project(src, target):
    with open(src) as src_file:
        project_data = json.load(src_file)
        enc_content = base64.b64decode(project_data['content'])
        key_bytes = b'11956722077380335572'
        iv_bytes = b'1103392056537578664'
        key = binascii.a2b_hex(hashlib.sha256(key_bytes).hexdigest())
        iv = binascii.a2b_hex(hashlib.md5(iv_bytes).hexdigest())
        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw_content = cipher.decrypt(enc_content)
        dctx = zstandard.ZstdDecompressor()
        decompressed = dctx.decompress(raw_content)
    with open(target, 'wb') as target_file:
        target_file.write(decompressed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='acep格式解密')
    parser.add_argument('src', type=str, help='acep加密工程文件路径')
    parser.add_argument('target', type=str, help='ace解密工程文件路径')
    args = parser.parse_args()
    decrypt_ace_studio_project(args.src, args.target)
