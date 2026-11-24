#!/usr/bin/env python3
"""
aes_lab.py - AES encryption lab: ECB vs GCM (Python 'cryptography' library)

The key is NEVER hard-coded. It is generated from the OS CSPRNG (os.urandom)
by 'genkey' and read from the AES_KEY environment variable by every other command.

Usage:
    python aes_lab.py genkey                       # print a fresh base64 256-bit key
    export AES_KEY=$(python aes_lab.py genkey)     # keep it in the environment only

    python aes_lab.py encrypt <in> <out.enc>       # AES-256-GCM, random 96-bit nonce per call
    python aes_lab.py decrypt <in.enc> <out>       # verifies the tag before returning data
    python aes_lab.py image   <outdir>             # ECB vs GCM visual comparison
    python aes_lab.py text    <outdir>             # ECB vs GCM on repeating text
    python aes_lab.py tamper  <outdir>             # flip a bit -> GCM tag check fails
"""
import base64
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK = 16
NONCE_LEN = 12   # 96-bit nonce, the recommended size for GCM


# ----------------------------------------------------------------- key handling
def generate_key():
    """256-bit key from the operating system's cryptographically secure RNG."""
    return os.urandom(32)


def load_key():
    """Read the key from the AES_KEY environment variable (base64)."""
    value = os.environ.get("AES_KEY")
    if not value:
        sys.exit("AES_KEY is not set. Run:  export AES_KEY=$(python aes_lab.py genkey)")
    key = base64.b64decode(value)
    if len(key) != 32:
        sys.exit("AES_KEY must decode to exactly 32 bytes (AES-256).")
    return key


# ------------------------------------------------------------------- primitives
def ecb_encrypt(key, data):
    """AES-ECB. Insecure: identical plaintext blocks give identical ciphertext blocks.
    ECB has no IV or nonce. Input is zero-padded to a multiple of 16 for the demo."""
    if len(data) % BLOCK:
        data += b"\x00" * (BLOCK - len(data) % BLOCK)
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def ecb_decrypt(key, data):
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def gcm_encrypt(key, data, aad=None):
    """AES-GCM with a fresh random nonce per call. Output = nonce || ciphertext || tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def gcm_decrypt(key, blob, aad=None):
    """Raises InvalidTag if the ciphertext, tag, nonce or AAD was modified."""
    nonce, rest = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, rest, aad)


def block_stats(ct):
    blocks = [ct[i:i + BLOCK] for i in range(0, len(ct), BLOCK)]
    return len(blocks), len(set(blocks))


# --------------------------------------------------------------------- commands
def cmd_encrypt(src, dst):
    key = load_key()
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(gcm_encrypt(key, data))
    print(f"encrypted {src} -> {dst} (AES-256-GCM, random nonce)")


def cmd_decrypt(src, dst):
    key = load_key()
    with open(src, "rb") as f:
        blob = f.read()
    try:
        data = gcm_decrypt(key, blob)
    except InvalidTag:
        sys.exit("AUTHENTICATION FAILED: file was modified or the key is wrong.")
    with open(dst, "wb") as f:
        f.write(data)
    print(f"decrypted {src} -> {dst} (tag verified)")


def make_test_image(size=256):
    """A grayscale picture with large flat areas (a worst case for ECB)."""
    from PIL import Image, ImageDraw
    img = Image.new("L", (size, size), 255)
    d = ImageDraw.Draw(img)
    d.ellipse((30, 30, 226, 226), fill=40)
    d.rectangle((70, 90, 110, 130), fill=255)
    d.rectangle((146, 90, 186, 130), fill=255)
    d.rectangle((80, 160, 176, 185), fill=200)
    d.rectangle((0, 0, 255, 14), fill=120)
    return img


def cmd_image(outdir):
    from PIL import Image
    key = load_key()
    os.makedirs(outdir, exist_ok=True)
    img = make_test_image()
    raw = img.tobytes()                       # 1 byte per pixel: 16 pixels = 1 AES block

    ecb_ct = ecb_encrypt(key, raw)
    gcm_blob = gcm_encrypt(key, raw)
    gcm_ct = gcm_blob[NONCE_LEN:-16]          # strip nonce and tag; keep the ciphertext only

    img.save(f"{outdir}/original.png")
    Image.frombytes("L", img.size, ecb_ct[:len(raw)]).save(f"{outdir}/ecb.png")
    Image.frombytes("L", img.size, gcm_ct[:len(raw)]).save(f"{outdir}/gcm.png")

    side = Image.new("L", (img.width * 3 + 40, img.height), 255)
    side.paste(img, (0, 0))
    side.paste(Image.open(f"{outdir}/ecb.png"), (img.width + 20, 0))
    side.paste(Image.open(f"{outdir}/gcm.png"), (img.width * 2 + 40, 0))
    side.save(f"{outdir}/comparison.png")

    for name, ct in (("plaintext", raw), ("AES-ECB ", ecb_ct), ("AES-GCM ", gcm_ct)):
        total, unique = block_stats(ct)
        print(f"{name}: {total} blocks, {unique} unique, {total - unique} repeated")
    print(f"saved images to {outdir}/ (original.png, ecb.png, gcm.png, comparison.png)")


def cmd_text(outdir):
    key = load_key()
    os.makedirs(outdir, exist_ok=True)
    # 16-byte records, so identical records line up exactly with AES blocks
    a, b = b"PAY ALICE  $0100", b"PAY BOB    $9999"
    plain = a * 4 + b + a * 3                                # 8 blocks, 7 of them identical
    ecb_ct = ecb_encrypt(key, plain)
    gcm_ct = gcm_encrypt(key, plain)[NONCE_LEN:-16]
    for name, ct in (("AES-ECB", ecb_ct), ("AES-GCM", gcm_ct)):
        print(f"--- {name} ciphertext, one 16-byte block per line ---")
        for i in range(0, len(ct), BLOCK):
            print(f"block {i // BLOCK:2d}: {ct[i:i + BLOCK].hex()}")
        total, unique = block_stats(ct)
        print(f"{total} blocks, {unique} unique, {total - unique} repeated\n")
    # GCM: encrypting the SAME data twice gives different output (random nonce)
    a, b = gcm_encrypt(key, plain), gcm_encrypt(key, plain)
    print("GCM, same plaintext encrypted twice, same key:")
    print("  nonce 1:", a[:NONCE_LEN].hex())
    print("  nonce 2:", b[:NONCE_LEN].hex())
    print("  outputs identical?", a == b)


def cmd_tamper(outdir):
    key = load_key()
    os.makedirs(outdir, exist_ok=True)
    message = b"PAY ALICE $100 - approved by finance"
    blob = gcm_encrypt(key, message)
    print("original plaintext :", message)
    print("GCM blob (hex)     :", blob.hex())

    # 1. untouched ciphertext decrypts fine
    print("\n[1] untouched ciphertext ->", gcm_decrypt(key, blob))

    # 2. flip one bit in the ciphertext body
    bad = bytearray(blob)
    bad[NONCE_LEN + 4] ^= 0x01
    print("\n[2] one bit flipped in ciphertext byte", NONCE_LEN + 4)
    try:
        gcm_decrypt(key, bytes(bad))
        print("    decrypted (NOT detected!)")
    except InvalidTag:
        print("    AES-GCM: InvalidTag -> authentication FAILED, no plaintext returned")

    # 3. flip one bit in the authentication tag
    bad = bytearray(blob)
    bad[-1] ^= 0x01
    print("\n[3] one bit flipped in the 16-byte tag")
    try:
        gcm_decrypt(key, bytes(bad))
        print("    decrypted (NOT detected!)")
    except InvalidTag:
        print("    AES-GCM: InvalidTag -> authentication FAILED")

    # 4. the same attack on ECB is silently accepted
    ecb_ct = bytearray(ecb_encrypt(key, message.ljust(48, b" ")))
    ecb_ct[4] ^= 0x01
    garbage = ecb_decrypt(key, bytes(ecb_ct))
    print("\n[4] same one-bit flip against AES-ECB (no authentication)")
    print("    decrypts without any error to:", garbage)


def main():
    cmds = {"encrypt": (cmd_encrypt, 2), "decrypt": (cmd_decrypt, 2),
            "image": (cmd_image, 1), "text": (cmd_text, 1), "tamper": (cmd_tamper, 1)}
    if len(sys.argv) >= 2 and sys.argv[1] == "genkey":
        print(base64.b64encode(generate_key()).decode())
    elif len(sys.argv) >= 2 and sys.argv[1] in cmds and len(sys.argv) == 2 + cmds[sys.argv[1]][1]:
        cmds[sys.argv[1]][0](*sys.argv[2:])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
