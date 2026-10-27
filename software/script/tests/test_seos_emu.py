#!/usr/bin/env python3
"""Unit tests for SEOS emulator CLI helpers (Wave 1)."""

import os
import sys
import unittest

CURRENT_DIR = os.path.split(os.path.abspath(__file__))[0]
config_path = CURRENT_DIR.rsplit(os.sep, 1)[0]
sys.path.append(config_path)

from chameleon_seos import (  # noqa: E402
    SEOS_ENCR_2K3DES,
    SEOS_ENCR_3K3DES,
    SEOS_ENCR_AES,
    SEOS_FACTORY_ADF_OID,
    SEOS_FACTORY_GDF_DIV,
    SEOS_FACTORY_GDF_OID,
    SEOS_HASH_SHA1,
    SEOS_HASH_SHA256,
    add_seos_gdf_args,
    build_seos_shill_authenticate,
    build_seos_shill_select_adf,
    format_seos_eview,
    pack_seos_emu_data,
    parse_seos_encr_alg,
    parse_seos_hash_alg,
    seos_encr_alg_name,
    seos_hash_alg_name,
    unpack_seos_emu_data,
)


class TestSeosAlgParse(unittest.TestCase):
    def test_parse_hash_names_and_hex(self):
        self.assertEqual(parse_seos_hash_alg("sha256"), SEOS_HASH_SHA256)
        self.assertEqual(parse_seos_hash_alg("SHA-256"), SEOS_HASH_SHA256)
        self.assertEqual(parse_seos_hash_alg("sha1"), SEOS_HASH_SHA1)
        self.assertEqual(parse_seos_hash_alg("07"), SEOS_HASH_SHA256)
        self.assertEqual(parse_seos_hash_alg("0x06"), SEOS_HASH_SHA1)

    def test_parse_encr_names_and_hex(self):
        self.assertEqual(parse_seos_encr_alg("aes"), SEOS_ENCR_AES)
        self.assertEqual(parse_seos_encr_alg("AES-128"), SEOS_ENCR_AES)
        self.assertEqual(parse_seos_encr_alg("2k3des"), SEOS_ENCR_2K3DES)
        self.assertEqual(parse_seos_encr_alg("3k3des"), SEOS_ENCR_3K3DES)
        self.assertEqual(parse_seos_encr_alg("09"), SEOS_ENCR_AES)
        self.assertEqual(parse_seos_encr_alg("0x02"), SEOS_ENCR_2K3DES)

    def test_parse_rejects_unknown(self):
        with self.assertRaises(ValueError):
            parse_seos_hash_alg("md5")
        with self.assertRaises(ValueError):
            parse_seos_encr_alg("none")

    def test_alg_names(self):
        self.assertEqual(seos_hash_alg_name(SEOS_HASH_SHA256), "SHA-256")
        self.assertEqual(seos_hash_alg_name(SEOS_HASH_SHA1), "SHA-1")
        self.assertEqual(seos_encr_alg_name(SEOS_ENCR_AES), "AES-128")
        self.assertEqual(seos_encr_alg_name(SEOS_ENCR_2K3DES), "2K3DES")
        self.assertEqual(seos_encr_alg_name(SEOS_ENCR_3K3DES), "3K3DES")


class TestSeosEViewFormat(unittest.TestCase):
    def test_eview_prints_algs_and_flags_but_not_keys(self):
        lines = format_seos_eview(
            {
                "data": bytes.fromhex("0500"),
                "oid": bytes.fromhex("030107090000000000"),
                "tag": bytes.fromhex("FF00"),
                "diversifier": bytes.fromhex("01020304050607"),
                "hash_alg": SEOS_HASH_SHA256,
                "encr_alg": SEOS_ENCR_AES,
            }
        )
        text = "\n".join(lines)
        self.assertIn("Data: 0500", text)
        self.assertIn("OID: 030107090000000000", text)
        self.assertIn("Tag: FF00", text)
        self.assertIn("Diversifier: 01020304050607", text)
        self.assertIn("Hash: SHA-256 (0x07)", text)
        self.assertIn("Encr: AES-128 (0x09)", text)
        self.assertIn("Flags: hash=SHA-256 encr=AES-128", text)
        self.assertNotIn("authkey", text.lower())
        self.assertNotIn("privenc", text.lower())
        self.assertNotIn("privmac", text.lower())


class TestSeosELoadArgs(unittest.TestCase):
    def test_eload_parser_accepts_hash_and_encr(self):
        import argparse

        from chameleon_seos import add_seos_alg_args

        parser = argparse.ArgumentParser()
        add_seos_alg_args(parser)
        args = parser.parse_args(["--hash", "sha256", "--encr", "aes"])
        self.assertEqual(args.hash, "sha256")
        self.assertEqual(args.encr, "aes")


class TestSeosPrivacyShill(unittest.TestCase):
    def test_select_shill_is_well_formed_cd_85_8e(self):
        rng = iter(bytes(range(0x40)) + bytes(range(0x10, 0x18)))
        body = build_seos_shill_select_adf(
            rng=lambda n: bytes(next(rng) for _ in range(n)),
            encr_alg=SEOS_ENCR_AES,
            hash_alg=SEOS_HASH_SHA256,
        )
        self.assertEqual(body[0], 0xCD)
        self.assertEqual(body[1], 0x02)
        self.assertEqual(body[2], SEOS_ENCR_AES)
        self.assertEqual(body[3], SEOS_HASH_SHA256)
        self.assertEqual(body[4], 0x85)
        self.assertEqual(body[5], 0x40)
        self.assertEqual(body[6:70], bytes(range(0x40)))
        self.assertEqual(body[70], 0x8E)
        self.assertEqual(body[71], 0x08)
        self.assertEqual(body[72:80], bytes(range(0x10, 0x18)))
        self.assertEqual(len(body), 80)

    def test_auth_shill_is_well_formed_7c_82(self):
        rng = iter(bytes(range(0x28)))
        body = build_seos_shill_authenticate(
            rng=lambda n: bytes(next(rng) for _ in range(n))
        )
        self.assertEqual(body[0], 0x7C)
        self.assertEqual(body[1], 0x2A)
        self.assertEqual(body[2], 0x82)
        self.assertEqual(body[3], 0x28)
        self.assertEqual(body[4:44], bytes(range(0x28)))
        self.assertEqual(len(body), 44)


class TestSeosGdfRecord(unittest.TestCase):
    def test_factory_gdf_is_distinct_from_adf(self):
        self.assertNotEqual(SEOS_FACTORY_GDF_OID, SEOS_FACTORY_ADF_OID)
        self.assertEqual(SEOS_FACTORY_GDF_OID, bytes.fromhex("03010709FFFFFFFFFF"))
        self.assertEqual(SEOS_FACTORY_GDF_DIV, bytes.fromhex("00000000000000"))

    def test_pack_unpack_roundtrip_includes_gdf(self):
        packed = pack_seos_emu_data(
            data=bytes.fromhex("0500"),
            oid=SEOS_FACTORY_ADF_OID,
            tag=bytes.fromhex("FF00"),
            diversifier=bytes.fromhex("01020304050607"),
            hash_alg=SEOS_HASH_SHA256,
            encr_alg=SEOS_ENCR_AES,
            gdf_oid=SEOS_FACTORY_GDF_OID,
            gdf_diversifier=SEOS_FACTORY_GDF_DIV,
        )
        parsed = unpack_seos_emu_data(packed)
        self.assertEqual(parsed["oid"], SEOS_FACTORY_ADF_OID)
        self.assertEqual(parsed["gdf_oid"], SEOS_FACTORY_GDF_OID)
        self.assertEqual(parsed["gdf_diversifier"], SEOS_FACTORY_GDF_DIV)
        self.assertEqual(parsed["hash_alg"], SEOS_HASH_SHA256)
        self.assertEqual(parsed["encr_alg"], SEOS_ENCR_AES)

    def test_unpack_legacy_payload_has_no_gdf(self):
        packed = pack_seos_emu_data(
            data=bytes.fromhex("0500"),
            oid=SEOS_FACTORY_ADF_OID,
            tag=bytes.fromhex("FF00"),
            diversifier=bytes.fromhex("01020304050607"),
            hash_alg=SEOS_HASH_SHA256,
            encr_alg=SEOS_ENCR_AES,
        )
        parsed = unpack_seos_emu_data(packed)
        self.assertNotIn("gdf_oid", parsed)

    def test_eview_prints_gdf_fields(self):
        lines = format_seos_eview(
            {
                "data": bytes.fromhex("0500"),
                "oid": SEOS_FACTORY_ADF_OID,
                "tag": bytes.fromhex("FF00"),
                "diversifier": bytes.fromhex("01020304050607"),
                "hash_alg": SEOS_HASH_SHA256,
                "encr_alg": SEOS_ENCR_AES,
                "gdf_oid": SEOS_FACTORY_GDF_OID,
                "gdf_diversifier": SEOS_FACTORY_GDF_DIV,
            }
        )
        text = "\n".join(lines)
        self.assertIn("GDF OID: 03010709FFFFFFFFFF", text)
        self.assertIn("GDF Diversifier: 00000000000000", text)
        self.assertIn("OID: 030107090000000000", text)

    def test_eload_parser_accepts_gdf_fields(self):
        import argparse

        parser = argparse.ArgumentParser()
        add_seos_gdf_args(parser)
        args = parser.parse_args(
            ["--gdf-oid", "03010709FFFFFFFFFF", "--gdf-div", "00000000000000"]
        )
        self.assertEqual(args.gdf_oid, "03010709FFFFFFFFFF")
        self.assertEqual(args.gdf_div, "00000000000000")


if __name__ == "__main__":
    unittest.main()
