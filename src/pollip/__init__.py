# Copyright (c) 2025 Quae
# SPDX-License-Identifier: BSD-3-Clause

"""pollip: Library for modifying Hollow Knight: Silksong save data."""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import pathlib
import typing as t

import mini_nrbf
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.padding import PKCS7

if t.TYPE_CHECKING:
    import collections.abc as cabc
    import os

    from cryptography.utils import Buffer

__all__ = ["open_save_file"]

AES_256_KEY = b"UKu52ePUBwetZ9wNX88o54dnfKRu0T1l"
AES_256_ECB_CIPHER = Cipher(AES256(AES_256_KEY), ECB())  # noqa: S305
PAD_BITS = 0x80


class _SaveFileRecords(t.NamedTuple):
    header: mini_nrbf.SerializedStreamHeader
    string: mini_nrbf.BinaryObjectString
    end: mini_nrbf.MessageEnd


class _Context(t.Protocol):
    def update(self, data: Buffer) -> bytes: ...
    def finalize(self) -> bytes: ...


def _parse_save_file_records(path: os.PathLike[str] | str) -> _SaveFileRecords:
    data = pathlib.Path(path).read_bytes()
    records = tuple(mini_nrbf.parse_bytes(data))
    return _SaveFileRecords(*t.cast("_SaveFileRecords", records))


def _apply(ctx: _Context, data: Buffer) -> bytes:
    return ctx.update(data) + ctx.finalize()


def _encrypt(data: Buffer) -> bytes:
    """Encrypt data using AES-256-ECB."""
    encryptor = AES_256_ECB_CIPHER.encryptor()
    return _apply(encryptor, data)


def _decrypt(data: Buffer) -> bytes:
    """Decrypt data using AES-256-ECB."""
    decryptor = AES_256_ECB_CIPHER.decryptor()
    return _apply(decryptor, data)


def _pad(data: Buffer, block_size: int = PAD_BITS) -> bytes:
    """Add PKCS#7 padding."""
    padder = PKCS7(block_size).padder()
    return _apply(padder, data)


def _unpad(data: Buffer, block_size: int = PAD_BITS) -> bytes:
    """Remove PKCS#7 padding."""
    unpadder = PKCS7(block_size).unpadder()
    return _apply(unpadder, data)


def _encrypt_json(json_data: dict[str, t.Any]) -> bytes:
    """Encrypt JSON data using AES-256-ECB."""
    json_string = json.dumps(json_data, separators=(",", ":"))
    ciphertext = _encrypt(_pad(json_string.encode("u8")))
    return base64.standard_b64encode(ciphertext)


def _decrypt_json(data: Buffer, *, strict: bool = True) -> t.Any:
    """Decrypt JSON data that was encrypted using AES-256-ECB."""
    try:
        ciphertext = base64.b64decode(data, validate=strict)
    except binascii.Error:
        msg = "malformed payload: invalid payload encoding"
        raise ValueError(msg) from None

    json_string = _unpad(_decrypt(ciphertext))
    return json.loads(json_string)


@contextlib.contextmanager
def open_save_file(
    path: os.PathLike[str] | str, *, read_only: bool = False
) -> cabc.Generator[dict[str, t.Any], None, None]:
    """
    Open an encrypted Hollow Knight: Silksong save file.

    The file is automatically decrypted and the decrypted JSON is returned.
    After leaving the context, the JSON data is encrypted and saved.

    Pass the `read_only` flag to avoid writing to the opened save file.
    """
    records = _parse_save_file_records(path)
    json_data = _decrypt_json(records.string.value.encode("u8"))

    try:
        yield json_data
    finally:
        if not read_only:
            records.string.value = _encrypt_json(json_data).decode("u8")
            _ = mini_nrbf.serialize_to_file(records, path)
