import argparse
import base64
import binascii
import hashlib
import json
import zstandard
from Crypto.Cipher import AES
from Crypto.Util import Padding


def encrypt_ace_studio_project(src, target):
    project_data = {}
    with open(src, 'rb') as src_file:
        raw_content = src_file.read()
        cctx = zstandard.ZstdCompressor()
        compressed = cctx.compress(raw_content)
        key_bytes = b'11956722077380335572'
        iv_bytes = b'1103392056537578664'
        key = hashlib.sha256(key_bytes).digest()
        iv = hashlib.md5(iv_bytes).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc_content = cipher.encrypt(Padding.pad(compressed, 16, 'iso7816'))
        project_data['content'] = base64.b64encode(enc_content).decode()
    project_data.update({"debugInfo":{"os":"windows","platform":"pc","version":"10"},"salt":"","version":1})
    with open(target, 'w') as target_file:
        json.dump(project_data, target_file, separators=(',', ':'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='acep格式加密')
    parser.add_argument('src', type=str, help='acep解密工程文件路径')
    parser.add_argument('target', type=str, help='ace加密工程文件路径')
    args = parser.parse_args()
    encrypt_ace_studio_project(args.src, args.target)
