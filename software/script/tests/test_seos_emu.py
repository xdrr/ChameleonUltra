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
    SEOS_HASH_SHA1,
    SEOS_HASH_SHA256,
    format_seos_eview,
    parse_seos_encr_alg,
    parse_seos_hash_alg,
    seos_encr_alg_name,
    seos_hash_alg_name,
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


if __name__ == "__main__":
    unittest.main()
