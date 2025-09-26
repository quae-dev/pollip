# Copyright (c) 2025 Quae
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import base64
import binascii
import json
import typing as t

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.padding import PKCS7

if t.TYPE_CHECKING:
    from cryptography.utils import Buffer

__all__ = ["decrypt_json", "encrypt_json"]

AES_256_KEY = b"UKu52ePUBwetZ9wNX88o54dnfKRu0T1l"
AES_256_ECB_CIPHER = Cipher(AES256(AES_256_KEY), ECB())  # noqa: S305
AES_BLOCK_SIZE = 128
PKCS7_PADDING = PKCS7(AES_BLOCK_SIZE)


def _encrypt(data: Buffer) -> bytes:
    """Encrypt data using AES-256-ECB."""
    encryptor = AES_256_ECB_CIPHER.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _decrypt(data: Buffer) -> bytes:
    """Decrypt data using AES-256-ECB."""
    decryptor = AES_256_ECB_CIPHER.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _pad(data: Buffer) -> bytes:
    """Add PKCS#7 padding."""
    padder = PKCS7_PADDING.padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: Buffer) -> bytes:
    """Remove PKCS#7 padding."""
    unpadder = PKCS7_PADDING.unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt_json(json_data: dict[str, t.Any]) -> bytes:
    """Encrypt JSON data using AES-256-ECB."""
    json_string = json.dumps(json_data, separators=(",", ":"))
    ciphertext = _encrypt(_pad(json_string.encode("u8")))
    return base64.standard_b64encode(ciphertext)


def decrypt_json(data: Buffer, *, strict: bool = True) -> t.Any:
    """Decrypt JSON data that was encrypted using AES-256-ECB."""
    try:
        ciphertext = base64.b64decode(data, validate=strict)
    except binascii.Error:
        msg = "malformed payload: invalid payload encoding"
        raise ValueError(msg) from None

    json_string = _unpad(_decrypt(ciphertext))
    return json.loads(json_string)
