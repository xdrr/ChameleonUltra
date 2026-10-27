"""SEOS emulator helpers shared by the CLI (algorithm names and eview)."""

from typing import Callable, Dict, Iterable, List, Mapping, Union

SEOS_HASH_SHA1 = 0x06
SEOS_HASH_SHA256 = 0x07
SEOS_ENCR_2K3DES = 0x02
SEOS_ENCR_3K3DES = 0x03
SEOS_ENCR_AES = 0x09

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
        f"[=]        Hash: {hash_name} (0x{hash_alg:02X})",
        f"[=]        Encr: {encr_name} (0x{encr_alg:02X})",
        f"[=]       Flags: hash={hash_name} encr={encr_name}",
    ]
    return lines
