"""
加密模块 — NaCl Box + AES-256-GCM + Ed25519 认证。

密钥派生流程：
  1. 配对阶段：客户端与服务端通过 NaCl Box 交换会话密钥
  2. 通信阶段：AES-256-GCM 加密传输数据
  3. 认证：Ed25519 签名验证消息完整性
"""

    masterSecret (32 bytes)
        └── deriveContentKeyPair() -> contentPublicKey + contentSecretKey
        └── random DEK (32 bytes) -> NaCl Box(DEK, contentPublicKey) -> wrappedDek
        └── envelope -> AES-256-GCM(DEK) -> ciphertext (base64)

Bundle format (from ``crypto/box.d.ts``)::

    ephemeral_pubkey(32) + nonce(24) + ciphertext
"""

import os
import hashlib
import hmac as hmac_lib
from typing import Optional

from nacl.bindings import (
    crypto_box_beforenm,
    crypto_box_afternm,
    crypto_box_open_afternm,
    crypto_box_keypair,
    crypto_secretbox,
    crypto_secretbox_open,
    crypto_sign_keypair,
    crypto_sign_seed_keypair,
    crypto_sign,
    crypto_sign_open,
)
from nacl.bindings import (
    randombytes as nacl_randombytes,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ──────────────────────────────────────────────
# NaCl Box constants  (X25519 + XSalsa20-Poly1305)
# ──────────────────────────────────────────────

BOX_KEY_SIZE = 32                           # X25519 key size in bytes
BOX_NONCE_SIZE = 24                         # XSalsa20 nonce size
BOX_BUNDLE_EPHEMERAL = 32                    # Ephemeral public key length
BOX_BUNDLE_NONCE = 24                        # Nonce length within a bundle
BOX_BUNDLE_OVERHEAD = BOX_BUNDLE_EPHEMERAL + BOX_BUNDLE_NONCE


def random_bytes(n: int) -> bytes:
    """Return *n* cryptographically secure random bytes."""
    return nacl_randombytes(n)


def generate_box_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair.

    Returns:
        Tuple of ``(public_key, secret_key)``, each 32 bytes.
    """
    return crypto_box_keypair()


def box_public_from_secret(sk: bytes) -> bytes:
    """Derive the X25519 public key from a secret key via scalar multiplication."""
    from nacl.bindings import crypto_scalarmult_base
    return crypto_scalarmult_base(sk)


def encrypt_box(plaintext: bytes, recipient_pk: bytes) -> bytes:
    """Encrypt *plaintext* with an ephemeral NaCl Box for *recipient_pk*.

    Bundle layout: ``ephemeral_pubkey(32) + nonce(24) + ciphertext``.

    Args:
        plaintext: Data to encrypt (any length).
        recipient_pk: Recipient's X25519 public key (32 bytes).

    Returns:
        Encrypted bundle bytes.
    """
    ephemeral_pk, ephemeral_sk = crypto_box_keypair()
    nonce = random_bytes(BOX_NONCE_SIZE)
    shared = crypto_box_beforenm(recipient_pk, ephemeral_sk)
    ciphertext = crypto_box_afternm(plaintext, nonce, shared)
    return ephemeral_pk + nonce + ciphertext


def decrypt_box(bundle: bytes, recipient_sk: bytes) -> Optional[bytes]:
    """Decrypt a NaCl Box *bundle* using the recipient's secret key.

    Args:
        bundle: Encrypted bundle (ephemeral_pk + nonce + ciphertext).
        recipient_sk: Recipient's X25519 secret key (32 bytes).

    Returns:
        Decrypted plaintext, or ``None`` if decryption fails.
    """
    if len(bundle) < BOX_BUNDLE_OVERHEAD:
        return None
    ephemeral_pk = bundle[:BOX_BUNDLE_EPHEMERAL]
    nonce = bundle[BOX_BUNDLE_EPHEMERAL:BOX_BUNDLE_EPHEMERAL + BOX_BUNDLE_NONCE]
    ciphertext = bundle[BOX_BUNDLE_EPHEMERAL + BOX_BUNDLE_NONCE:]
    shared = crypto_box_beforenm(ephemeral_pk, recipient_sk)
    try:
        return crypto_box_open_afternm(ciphertext, nonce, shared)
    except Exception:
        return None


# ──────────────────────────────────────────────
# AES-256-GCM  (matching ``crypto/session.d.ts``)
# ──────────────────────────────────────────────

AES_KEY_SIZE = 32     # AES-256 key length
AES_NONCE_SIZE = 12   # GCM standard nonce length


def encrypt_aes_gcm(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Encrypt *plaintext* with AES-256-GCM.

    Returns ``nonce(12) + ciphertext + tag(16)`` concatenated.

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES-256 key.
        aad: Optional additional authenticated data (default: empty).

    Returns:
        Nonce-prepended ciphertext with authentication tag.
    """
    aesgcm = AESGCM(key)
    nonce = random_bytes(AES_NONCE_SIZE)
    return nonce + aesgcm.encrypt(nonce, plaintext, aad)


def decrypt_aes_gcm(ciphertext: bytes, key: bytes, aad: bytes = b"") -> Optional[bytes]:
    """Decrypt an AES-256-GCM payload.

    Input is expected to be ``nonce(12) + ciphertext + tag(16)``.

    Args:
        ciphertext: Nonce-prepended ciphertext.
        key: 32-byte AES-256 key.
        aad: Additional authenticated data used during encryption.

    Returns:
        Decrypted plaintext, or ``None`` on failure.
    """
    if len(ciphertext) < AES_NONCE_SIZE + 16:
        return None
    nonce = ciphertext[:AES_NONCE_SIZE]
    ct = ciphertext[AES_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        return None


# ──────────────────────────────────────────────
# Key derivation  (matching ``crypto/keys.d.ts``)
# ──────────────────────────────────────────────

def derive_key_tree_root(seed: bytes, usage: str) -> tuple[bytes, bytes]:
    """Derive a root key and chain code from a seed for a given *usage* context.

    Uses ``HMAC-SHA512(encode(usage + " Master Seed"), seed)``.

    Returns:
        Tuple of ``(key, chainCode)``, each 32 bytes.
    """
    h = hmac_lib.new(
        (usage + " Master Seed").encode("utf-8"),
        seed,
        hashlib.sha512,
    )
    digest = h.digest()
    return digest[:32], digest[32:]


def derive_key_tree_child(chain_code: bytes, index: str) -> tuple[bytes, bytes]:
    """Derive a child key and chain code from a parent chain code and an *index* label.

    Uses ``HMAC-SHA512(parentChainCode, [0x00, ...encode(index)])``.
    """
    data = b"\x00" + index.encode("utf-8")
    h = hmac_lib.new(chain_code, data, hashlib.sha512)
    digest = h.digest()
    return digest[:32], digest[32:]


def derive_key(master: bytes, usage: str, path: list[str]) -> bytes:
    """Derive a key by walking a derivation path from the *master* seed.

    Args:
        master: Root seed material (32 bytes).
        usage: Domain string (e.g. ``"encryption"``).
        path: Ordered list of path segments (e.g. ``["content"]``).

    Returns:
        Derived 32-byte key.
    """
    key, chain = derive_key_tree_root(master, usage)
    for segment in path:
        key, chain = derive_key_tree_child(chain, segment)
    return key


# ──────────────────────────────────────────────
# Content key pair derivation
# ──────────────────────────────────────────────

def derive_content_keypair(master_secret: bytes) -> tuple[bytes, bytes]:
    """Derive a content NaCl Box keypair from the *master_secret*.

    Derivation path: ``masterSecret -> "encryption" -> "content" -> key``.
    The secret key is the derived key; the public key is derived from it
    via Curve25519 scalar multiplication.

    Returns:
        Tuple of ``(public_key, secret_key)``.
    """
    sk = derive_key(master_secret, "encryption", ["content"])
    pk = box_public_from_secret(sk)
    return pk, sk


# ──────────────────────────────────────────────
# Session key management
# ──────────────────────────────────────────────

def generate_session_keys(master_secret: bytes) -> tuple[bytes, str]:
    """Generate a per-session data encryption key (DEK) and wrap it with NaCl Box.

    Args:
        master_secret: The shared master secret (32 bytes).

    Returns:
        Tuple of ``(dek, wrapped_dek_base64)``.
        The wrapped key is prefixed with version byte ``\\x00``.
    """
    content_pk, _ = derive_content_keypair(master_secret)
    dek = random_bytes(AES_KEY_SIZE)           # 32-byte AES-256 key
    bundle = encrypt_box(dek, content_pk)
    # Prepend version byte (0) to the bundle
    import base64
    wrapped = b"\x00" + bundle
    return dek, base64.b64encode(wrapped).decode("ascii")


def unwrap_session_key(wrapped_dek_base64: str, master_secret: bytes) -> Optional[bytes]:
    """Unwrap a session DEK from its base64-encoded wrapped representation.

    Args:
        wrapped_dek_base64: Base64-encoded wrapped DEK (version byte + bundle).
        master_secret: The shared master secret (32 bytes).

    Returns:
        The 32-byte DEK, or ``None`` on failure.
    """
    import base64
    try:
        wrapped = base64.b64decode(wrapped_dek_base64)
        if len(wrapped) < 1 or wrapped[0] != 0:
            return None
        _, content_sk = derive_content_keypair(master_secret)
        return decrypt_box(wrapped[1:], content_sk)
    except Exception:
        return None


def encrypt_envelope(data: object, dek: bytes) -> str:
    """Encrypt a JSON-serializable *data* object with AES-256-GCM.

    Returns the ciphertext as a base64-encoded ASCII string.
    """
    import json
    import base64
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ct = encrypt_aes_gcm(plaintext, dek)
    return base64.b64encode(ct).decode("ascii")


def decrypt_envelope(ciphertext_b64: str, dek: bytes) -> Optional[object]:
    """Decrypt a base64 AES-256-GCM *ciphertext_b64* back to the original data.

    Returns the deserialized Python object, or ``None`` on failure.
    """
    import json
    import base64
    try:
        ct = base64.b64decode(ciphertext_b64)
        plaintext = decrypt_aes_gcm(ct, dek)
        if plaintext is None:
            return None
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None


# ──────────────────────────────────────────────
# Ed25519 authentication  (matching ``crypto/auth.d.ts``)
# ──────────────────────────────────────────────

def auth_challenge(seed: bytes) -> dict:
    """Generate an authentication challenge signed with an Ed25519 key derived from *seed*.

    Uses tweetnacl-style key generation where the seed is used directly
    as the Ed25519 seed.

    Returns:
        Dict with ``challenge`` (nonce), ``publicKey``, and ``signature`` bytes.
    """
    pk, sk = crypto_sign_seed_keypair(seed)
    nonce = random_bytes(32)
    signature = crypto_sign(nonce, sk)
    # crypto_sign returns the signed message (signature prepended to message)
    actual_sig = signature[:64]
    return {
        "challenge": nonce,
        "publicKey": pk,
        "signature": actual_sig,
    }


def sign_challenge(nonce: bytes, seed: bytes) -> dict:
    """Sign a server-issued challenge *nonce* with a key derived from *seed*.

    Returns:
        Dict with ``publicKey`` and ``signature`` (first 64 bytes) bytes.
    """
    pk, sk = crypto_sign_seed_keypair(seed)
    signed = crypto_sign(nonce, sk)
    return {
        "publicKey": pk,
        "signature": signed[:64],
    }


def verify_challenge(challenge: bytes, public_key: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 *signature* over the given *challenge*.

    Args:
        challenge: The original challenge bytes.
        public_key: Ed25519 public key (32 bytes).
        signature: Ed25519 signature (64 bytes).

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        crypto_sign_open(signature + challenge, public_key)
        return True
    except Exception:
        return False
