import sys
import os

kexp_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(kexp_dir, '../../'))

from TLS.kuznyechik.mac import CMAC
from TLS.kuznyechik.block_cipher import Kuznyechik
from TLS.kuznyechik.block_cipher_mode import CTR_ACPKM

def expand_key(k, k_mac, k_enc, iv):
    block_cipher = Kuznyechik()
    cmac = CMAC(block_cipher, 16)
    enc = CTR_ACPKM(block_cipher, 32, 16)

    keymac = cmac.calculate(iv + k, k_mac)
    kexp = enc.encrypt(k + keymac, k_enc, iv)
    return kexp

def import_key(kexp, k_mac, k_enc, iv):
    block_cipher = Kuznyechik()
    cmac = CMAC(block_cipher, 16)
    enc = CTR_ACPKM(block_cipher, 32, 16)

    k_keymac = enc.decrypt(kexp, k_enc, iv)
    k, keymac = k_keymac[:-16], k_keymac[-16:]
    keymac_calculated = cmac.calculate(iv + k, k_mac)
    if keymac != keymac_calculated:
        raise ValueError('macs do not match!')
    return k
