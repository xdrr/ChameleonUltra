"""SEOS emulator helpers shared by the CLI (algorithm names and eview)."""

from typing import Callable, Dict, Iterable, List, Mapping, Optional, Union

SEOS_HASH_SHA1 = 0x06
SEOS_HASH_SHA256 = 0x07
SEOS_ENCR_2K3DES = 0x02
SEOS_ENCR_3K3DES = 0x03
SEOS_ENCR_AES = 0x09

# Factory ADF is the public Zero-Key OID. Factory GDF is a distinct
# research placeholder so 00 A5 07 does not replay ADF contents.
SEOS_FACTORY_ADF_OID = bytes.fromhex("030107090000000000")
SEOS_FACTORY_GDF_OID = bytes.fromhex("03010709FFFFFFFFFF")
SEOS_FACTORY_GDF_DIV = bytes.fromhex("00000000000000")

_HASH_BY_NAME = {
    "sha1": SEOS_HASH_SHA1,
    "sha-1": SEOS_HASH_SHA1,
    "sha256": SEOS_HASH_SHA256,
    "sha-256": SEOS_HASH_SHA256,
}
_ENCR_BY_NAME = {
    "aes": SEOS_ENCR_AES,
    "aes128": SEOS_ENCR_AES,
    "aes-128": SEOS_ENCR_AES,
    "2k3des": SEOS_ENCR_2K3DES,
    "3k3des": SEOS_ENCR_3K3DES,
}
_HASH_NAMES = {
    SEOS_HASH_SHA1: "SHA-1",
    SEOS_HASH_SHA256: "SHA-256",
}
_ENCR_NAMES = {
    SEOS_ENCR_AES: "AES-128",
    SEOS_ENCR_2K3DES: "2K3DES",
    SEOS_ENCR_3K3DES: "3K3DES",
}


def _parse_alg(value: str, names: Mapping[str, int], known: Iterable[int]) -> int:
    text = value.strip().lower()
    if text in names:
        return names[text]
    if text.startswith("0x"):
        code = int(text, 16)
    elif all(c in "0123456789abcdef" for c in text) and len(text) <= 2:
        code = int(text, 16)
    else:
        raise ValueError(f"Unknown SEOS algorithm: {value}")
    if code not in known:
        raise ValueError(f"Unknown SEOS algorithm: {value}")
    return code


def parse_seos_hash_alg(value: str) -> int:
    return _parse_alg(value, _HASH_BY_NAME, _HASH_NAMES)


def parse_seos_encr_alg(value: str) -> int:
    return _parse_alg(value, _ENCR_BY_NAME, _ENCR_NAMES)


def seos_hash_alg_name(code: int) -> str:
    return _HASH_NAMES.get(code, f"0x{code:02X}")


def seos_encr_alg_name(code: int) -> str:
    return _ENCR_NAMES.get(code, f"0x{code:02X}")


def add_seos_alg_args(parser) -> None:
    parser.add_argument(
        "--hash",
        type=str,
        default=None,
        metavar="<alg>",
        help="Hash algorithm: sha256, sha1, or hex (06/07).",
    )
    parser.add_argument(
        "--encr",
        type=str,
        default=None,
        metavar="<alg>",
        help="Encryption algorithm: aes, 2k3des, 3k3des, or hex (02/03/09).",
    )


def add_seos_gdf_args(parser) -> None:
    parser.add_argument(
        "--gdf-oid",
        type=str,
        default=None,
        metavar="<hex>",
        help="Global DF OID (1-32 bytes). Distinct from the ADF OID.",
    )
    parser.add_argument(
        "--gdf-div",
        type=str,
        default=None,
        metavar="<hex>",
        help="Global DF diversifier (1-16 bytes).",
    )


def _tlv_put(value: bytes) -> bytes:
    return bytes([len(value)]) + value


def _tlv_take(payload: bytes, offset: int) -> tuple:
    if offset >= len(payload):
        raise ValueError("Truncated SEOS emu payload")
    length = payload[offset]
    start = offset + 1
    end = start + length
    if end > len(payload):
        raise ValueError("Truncated SEOS emu payload")
    return payload[start:end], end


def pack_seos_emu_data(
    data: bytes,
    oid: bytes,
    tag: bytes,
    diversifier: bytes,
    hash_alg: int,
    encr_alg: int,
    gdf_oid: Optional[bytes] = None,
    gdf_diversifier: Optional[bytes] = None,
    extras: Optional[Iterable[tuple]] = None,
) -> bytes:
    payload = (
        _tlv_put(data)
        + _tlv_put(oid)
        + _tlv_put(tag)
        + _tlv_put(diversifier)
        + bytes([hash_alg & 0xFF, encr_alg & 0xFF])
    )
    if gdf_oid is not None and gdf_diversifier is not None:
        payload += _tlv_put(gdf_oid) + _tlv_put(gdf_diversifier)
        if extras is not None:
            extra_list = list(extras)
            payload += bytes([len(extra_list)])
            for extra_tag, extra_data in extra_list:
                payload += _tlv_put(bytes(extra_tag)) + _tlv_put(bytes(extra_data))
    return payload


def unpack_seos_emu_data(payload: bytes) -> Dict[str, Union[bytes, int, List]]:
    data, offset = _tlv_take(payload, 0)
    oid, offset = _tlv_take(payload, offset)
    tag, offset = _tlv_take(payload, offset)
    diversifier, offset = _tlv_take(payload, offset)
    if offset + 2 > len(payload):
        raise ValueError("Truncated SEOS emu payload")
    parsed: Dict[str, Union[bytes, int, List]] = {
        "data": data,
        "oid": oid,
        "tag": tag,
        "diversifier": diversifier,
        "hash_alg": payload[offset],
        "encr_alg": payload[offset + 1],
    }
    offset += 2
    if offset < len(payload):
        gdf_oid, offset = _tlv_take(payload, offset)
        gdf_diversifier, offset = _tlv_take(payload, offset)
        parsed["gdf_oid"] = gdf_oid
        parsed["gdf_diversifier"] = gdf_diversifier
    if offset < len(payload):
        count = payload[offset]
        offset += 1
        extras = []
        for _ in range(count):
            extra_tag, offset = _tlv_take(payload, offset)
            extra_data, offset = _tlv_take(payload, offset)
            extras.append((extra_tag, extra_data))
        parsed["extras"] = extras
    return parsed


SEOS_SHILL_SELECT_CRYPTOGRAM_LEN = 0x40
SEOS_SHILL_SELECT_CMAC_LEN = 0x08
SEOS_SHILL_AUTH_BODY_LEN = 0x28


def build_seos_shill_select_adf(
    rng: Callable[[int], bytes],
    encr_alg: int = SEOS_ENCR_AES,
    hash_alg: int = SEOS_HASH_SHA256,
) -> bytes:
    """Well-formed random SELECT ADF reply. Does not leak file-not-found."""
    return (
        bytes([0xCD, 0x02, encr_alg, hash_alg, 0x85, SEOS_SHILL_SELECT_CRYPTOGRAM_LEN])
        + rng(SEOS_SHILL_SELECT_CRYPTOGRAM_LEN)
        + bytes([0x8E, SEOS_SHILL_SELECT_CMAC_LEN])
        + rng(SEOS_SHILL_SELECT_CMAC_LEN)
    )


def build_seos_shill_authenticate(rng: Callable[[int], bytes]) -> bytes:
    """Well-formed random GA2 reply. Failed auth looks like a cryptogram, not 6A82."""
    return bytes(
        [0x7C, SEOS_SHILL_AUTH_BODY_LEN + 2, 0x82, SEOS_SHILL_AUTH_BODY_LEN]
    ) + rng(SEOS_SHILL_AUTH_BODY_LEN)


def format_seos_eview(data: Dict[str, Union[bytes, int]]) -> List[str]:
    hash_alg = int(data["hash_alg"])
    encr_alg = int(data["encr_alg"])
    hash_name = seos_hash_alg_name(hash_alg)
    encr_name = seos_encr_alg_name(encr_alg)
    lines = [
        f"[=]        Data: {bytes(data['data']).hex().upper()}",
        f"[=]         OID: {bytes(data['oid']).hex().upper()}",
        f"[=]         Tag: {bytes(data['tag']).hex().upper()}",
        f"[=] Diversifier: {bytes(data['diversifier']).hex().upper()}",
    ]
    if "gdf_oid" in data:
        lines.append(f"[=]     GDF OID: {bytes(data['gdf_oid']).hex().upper()}")
        lines.append(
            f"[=] GDF Diversifier: {bytes(data['gdf_diversifier']).hex().upper()}"
        )
    extras = data.get("extras")
    if extras:
        for extra_tag, extra_data in extras:
            lines.append(
                f"[=]      Object: {bytes(extra_tag).hex().upper()} "
                f"{bytes(extra_data).hex().upper()}"
            )
    lines.extend(
        [
            f"[=]        Hash: {hash_name} (0x{hash_alg:02X})",
            f"[=]        Encr: {encr_name} (0x{encr_alg:02X})",
            f"[=]       Flags: hash={hash_name} encr={encr_name}",
        ]
    )
    return lines


SEOS_KEYSLOT_WRITE = 0x02
SEOS_SW_SM_MISSING = 0x6987
SEOS_SW_SM_INCORRECT = 0x6988


def seos_auth_master_for_keyslot(
    keyslot: int, read_key: bytes, write_key: bytes
) -> bytes:
    """Flipper: P2 0x02 is the ADF write master; anything else is the read master."""
    if keyslot == SEOS_KEYSLOT_WRITE:
        return write_key
    return read_key


def add_seos_write_key_arg(parser) -> None:
    parser.add_argument(
        "-w",
        "--write",
        type=str,
        default=None,
        metavar="<hex>",
        help="Write-auth key (16 bytes). Used when the reader sends P2=02.",
    )


def pack_seos_emu_keys(
    auth: bytes,
    privenc: bytes,
    privmac: bytes,
    auth_write: Optional[bytes] = None,
) -> bytes:
    payload = auth + privenc + privmac
    if auth_write is not None:
        payload += auth_write
    return payload


def unpack_seos_emu_keys(payload: bytes) -> Dict[str, bytes]:
    if len(payload) not in (48, 64):
        raise ValueError("SEOS key payload must be 48 or 64 bytes")
    parsed = {
        "auth": payload[0:16],
        "privenc": payload[16:32],
        "privmac": payload[32:48],
    }
    if len(payload) == 64:
        parsed["auth_write"] = payload[48:64]
    return parsed


def seos_parse_put_object(
    plaintext: bytes, default_tag: bytes = bytes.fromhex("FF00")
) -> tuple:
    """UPDATE DATA plaintext is tag || length || value, or length || value."""
    if len(plaintext) >= 3:
        tag = plaintext[0:2]
        length = plaintext[2]
        if length > 0 and len(plaintext) >= 3 + length:
            return tag, plaintext[3 : 3 + length]
    if len(plaintext) >= 1:
        length = plaintext[0]
        if length > 0 and len(plaintext) >= 1 + length:
            return default_tag, plaintext[1 : 1 + length]
    raise ValueError("UPDATE DATA object is truncated")


def seos_read_ber_tag(data: bytes, offset: int) -> tuple:
    if offset >= len(data):
        raise ValueError("truncated tag")
    if (data[offset] & 0x1F) == 0x1F:
        if offset + 1 >= len(data):
            raise ValueError("truncated tag")
        return data[offset : offset + 2], offset + 2
    return data[offset : offset + 1], offset + 1


def seos_parse_requested_tags(plaintext: bytes) -> List[bytes]:
    """GET DATA plaintext is a 5C tag list or a 4D extended header list."""
    if len(plaintext) < 3 or plaintext[0] not in (0x5C, 0x4D):
        raise ValueError("GET DATA field is not a tag list")
    body_len = plaintext[1]
    if body_len == 0 or len(plaintext) < 2 + body_len:
        raise ValueError("GET DATA field is truncated")
    end = 2 + body_len
    offset = 2
    tags: List[bytes] = []
    while offset < end:
        tag, offset = seos_read_ber_tag(plaintext, offset)
        if plaintext[0] == 0x4D:
            if offset >= end or plaintext[offset] != 0x00:
                raise ValueError("extended header list needs zero lengths")
            offset += 1
        tags.append(tag)
    if plaintext[0] == 0x5C and len(tags) != 1:
        raise ValueError("tag list names exactly one object")
    if not tags:
        raise ValueError("GET DATA field names no tags")
    return tags


def seos_collect_objects(
    store: Iterable[tuple], tags: Iterable[bytes]
) -> bytes:
    """Concatenate stored TLV objects named by the reader. Unknown tags add nothing."""
    objects = {bytes(tag): bytes(value) for tag, value in store}
    blob = b""
    for tag in tags:
        value = objects.get(bytes(tag))
        if value is None:
            continue
        blob += bytes(tag) + bytes([len(value)]) + value
    return blob


def seos_parse_object_arg(value: str) -> tuple:
    tag_hex, sep, data_hex = value.partition(":")
    if not sep or not tag_hex or not data_hex:
        raise ValueError("object must be <tag>:<hex>")
    tag = bytes.fromhex(tag_hex)
    data = bytes.fromhex(data_hex)
    if not (1 <= len(tag) <= 2) or not (1 <= len(data) <= 255):
        raise ValueError("object tag is 1-2 bytes and data is 1-255 bytes")
    return tag, data


def add_seos_object_arg(parser) -> None:
    parser.add_argument(
        "--object",
        action="append",
        default=None,
        metavar="<tag:hex>",
        help="Extra ADF object (repeatable), e.g. FF41:DEADBEEF.",
    )


def seos_ber_length(n: int) -> bytes:
    """ISO7816 BER length. Values 128-255 need the 0x81 long form."""
    if n < 0 or n > 255:
        raise ValueError("BER length out of range")
    if n < 128:
        return bytes([n])
    return bytes([0x81, n])


def seos_iblock_reassemble(parts: Iterable[bytes]) -> bytes:
    """Concatenate ISO14443-4 chained I-block INF payloads into one APDU."""
    chunks = list(parts)
    if not chunks:
        raise ValueError("I-block chain is empty")
    return b"".join(bytes(part) for part in chunks)


def seos_iso7816_more_sw(remaining: int) -> int:
    """ISO7816 61 xx: xx is leftover bytes, or 00 when more than 255 remain."""
    if remaining <= 0:
        return 0x9000
    if remaining > 255:
        return 0x6100
    return 0x6100 | remaining


def seos_iso7816_split_response(
    body: bytes, max_frame: int
) -> tuple:
    """Split a wrapped RAPDU so one T=CL frame can carry it.

    Two bytes of every frame are the status word. What does not fit is
    kept for GET RESPONSE (00 C0).
    """
    if max_frame < 2:
        raise ValueError("ISO7816 frame is too small")
    room = max_frame - 2
    if len(body) <= room:
        return bytes(body), b"", 0x9000
    return bytes(body[:room]), bytes(body[room:]), seos_iso7816_more_sw(len(body) - room)


def seos_iso7816_continue(
    leftover: bytes, le: int, max_frame: int
) -> tuple:
    """Serve GET RESPONSE. Le 0 asks for 256. Nothing pending is 6A86."""
    if max_frame < 2:
        raise ValueError("ISO7816 frame is too small")
    if not leftover:
        return b"", b"", 0x6A86
    asked = 256 if le == 0 else le
    room = max_frame - 2
    if room > asked:
        room = asked
    chunk = leftover[:room]
    rest = leftover[room:]
    sw = seos_iso7816_more_sw(len(rest)) if rest else 0x9000
    return bytes(chunk), bytes(rest), sw


def seos_sm_mac_objects(body: bytes) -> tuple:
    """Split an SM body into DOs covered by the MAC (including 97) and the 8E CMAC."""
    offset = 0
    mac_end = None
    cmac = None
    while offset + 2 <= len(body):
        tag = body[offset]
        length = body[offset + 1]
        header = 2
        if length & 0x80:
            extra = length & 0x7F
            if extra != 1 or offset + 2 + extra > len(body):
                raise ValueError("incorrect")
            length = body[offset + 2]
            header = 3
        end = offset + header + length
        if end > len(body):
            raise ValueError("incorrect")
        if tag == 0x8E:
            mac_end = offset
            cmac = body[offset + header : end]
            break
        offset = end
    if mac_end is None or cmac is None:
        raise ValueError("missing")
    return body[:mac_end], cmac
