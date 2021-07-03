import FairplayKSM

from uuid import uuid4
from base64 import b64encode
from typing import Tuple


ask = b'\x20'*16

with open('test_data/dev_private_key.pem', 'rb') as p_key_file:
    p_key_pem = p_key_file.read()

def get_key(asset_id: bytes) -> Tuple[bytes, bytes]:
    iv = b'\x00'*16
    key = b'\x22'*16
    return iv, key

with open("test_data/spc.bin", 'rb') as file:
    spc = file.read()
    key_ref = uuid4()
    asset_id = b64encode(key_ref.bytes)
    print(FairplayKSM.generate_ckc(
        key_ref=asset_id,
        spc=spc,
        key_fetch_callback=get_key,
        p_key_pem=p_key_pem,
        ask=ask
    ))