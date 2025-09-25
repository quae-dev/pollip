# Copyright (c) 2025 Quae
# SPDX-License-Identifier: BSD-3-Clause

"""pollip: Library for modifying Hollow Knight: Silksong save data."""

from __future__ import annotations

import contextlib
import pathlib
import typing as t

import mini_nrbf

from pollip import crypto

if t.TYPE_CHECKING:
    import collections.abc as cabc
    import os


__all__ = ["open_save_file"]


class _SaveFileRecords(t.NamedTuple):
    header: mini_nrbf.SerializedStreamHeader
    string: mini_nrbf.BinaryObjectString
    end: mini_nrbf.MessageEnd


def _parse_save_file_records(path: os.PathLike[str] | str) -> _SaveFileRecords:
    data = pathlib.Path(path).read_bytes()
    records = tuple(mini_nrbf.parse_bytes(data))
    return _SaveFileRecords(*t.cast("_SaveFileRecords", records))


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
    json_data = crypto.decrypt_json(records.string.value.encode("u8"))

    try:
        yield json_data
    finally:
        if not read_only:
            records.string.value = crypto.encrypt_json(json_data).decode("u8")
            _ = mini_nrbf.serialize_to_file(records, path)
