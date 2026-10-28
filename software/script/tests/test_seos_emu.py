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
    SEOS_KEYSLOT_WRITE,
    SEOS_SW_SM_INCORRECT,
    SEOS_SW_SM_MISSING,
    add_seos_gdf_args,
    add_seos_write_key_arg,
    build_seos_shill_authenticate,
    build_seos_shill_select_adf,
    format_seos_eview,
    pack_seos_emu_data,
    pack_seos_emu_keys,
    parse_seos_encr_alg,
    parse_seos_hash_alg,
    seos_auth_master_for_keyslot,
    seos_encr_alg_name,
    seos_hash_alg_name,
    seos_parse_put_object,
    seos_collect_objects,
    seos_iblock_reassemble,
    seos_iso7816_continue,
    seos_iso7816_more_sw,
    seos_iso7816_split_response,
    seos_parse_object_arg,
    seos_parse_requested_tags,
    seos_sm_mac_objects,
    unpack_seos_emu_data,
    unpack_seos_emu_keys,
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


class TestSeosAuthKeyslot(unittest.TestCase):
    def test_p2_02_selects_write_master(self):
        read_key = bytes(range(16))
        write_key = bytes(range(16, 32))
        self.assertEqual(
            seos_auth_master_for_keyslot(SEOS_KEYSLOT_WRITE, read_key, write_key),
            write_key,
        )
        self.assertEqual(
            seos_auth_master_for_keyslot(0x01, read_key, write_key), read_key
        )
        self.assertEqual(
            seos_auth_master_for_keyslot(0x00, read_key, write_key), read_key
        )

    def test_keys_parser_accepts_write_key(self):
        import argparse

        parser = argparse.ArgumentParser()
        add_seos_write_key_arg(parser)
        args = parser.parse_args(["--write", "00112233445566778899AABBCCDDEEFF"])
        self.assertEqual(args.write, "00112233445566778899AABBCCDDEEFF")

    def test_pack_unpack_keys_optional_write(self):
        auth = bytes(range(16))
        privenc = bytes(range(16, 32))
        privmac = bytes(range(32, 48))
        write = bytes(range(48, 64))
        packed = pack_seos_emu_keys(auth, privenc, privmac)
        self.assertEqual(len(packed), 48)
        parsed = unpack_seos_emu_keys(packed)
        self.assertEqual(parsed["auth"], auth)
        self.assertNotIn("auth_write", parsed)
        packed_w = pack_seos_emu_keys(auth, privenc, privmac, write)
        self.assertEqual(len(packed_w), 64)
        parsed_w = unpack_seos_emu_keys(packed_w)
        self.assertEqual(parsed_w["auth_write"], write)


class TestSeosUpdateData(unittest.TestCase):
    def test_parse_put_object_tag_len_value(self):
        tag, value = seos_parse_put_object(bytes.fromhex("FF000412345678"))
        self.assertEqual(tag, bytes.fromhex("FF00"))
        self.assertEqual(value, bytes.fromhex("12345678"))

    def test_parse_put_object_rejects_truncated(self):
        with self.assertRaises(ValueError):
            seos_parse_put_object(bytes.fromhex("FF00"))
        with self.assertRaises(ValueError):
            seos_parse_put_object(bytes.fromhex("FF0005AABB"))

    def test_parse_put_object_length_prefixed_uses_default_tag(self):
        tag, value = seos_parse_put_object(bytes.fromhex("0412345678"))
        self.assertEqual(tag, bytes.fromhex("FF00"))
        self.assertEqual(value, bytes.fromhex("12345678"))


class TestSeosSecureMessaging(unittest.TestCase):
    def test_sm_status_words(self):
        self.assertEqual(SEOS_SW_SM_MISSING, 0x6987)
        self.assertEqual(SEOS_SW_SM_INCORRECT, 0x6988)

    def test_mac_objects_include_protected_le(self):
        body = bytes.fromhex("8510" + "11" * 16 + "9700" + "8E08" + "22" * 8)
        objects, cmac = seos_sm_mac_objects(body)
        self.assertEqual(objects, bytes.fromhex("8510" + "11" * 16 + "9700"))
        self.assertEqual(cmac, bytes.fromhex("22" * 8))

    def test_missing_checksum_is_missing_do(self):
        with self.assertRaises(ValueError) as err:
            seos_sm_mac_objects(bytes.fromhex("8510" + "11" * 16 + "9700"))
        self.assertEqual(str(err.exception), "missing")


class TestSeosIBlockReassembly(unittest.TestCase):
    def test_reassemble_concatenates_chained_inf(self):
        first = bytes.fromhex("0CCB3FFF")
        second = bytes.fromhex("8510" + "11" * 16)
        self.assertEqual(seos_iblock_reassemble([first, second]), first + second)

    def test_reassemble_single_block_is_identity(self):
        apdu = bytes.fromhex("00A404000A")
        self.assertEqual(seos_iblock_reassemble([apdu]), apdu)

    def test_reassemble_rejects_empty(self):
        with self.assertRaises(ValueError):
            seos_iblock_reassemble([])


class TestSeosGetResponse(unittest.TestCase):
    def test_short_response_is_one_frame_with_9000(self):
        body = bytes.fromhex("851011223344")
        chunk, leftover, sw = seos_iso7816_split_response(body, max_frame=32)
        self.assertEqual(chunk, body)
        self.assertEqual(leftover, b"")
        self.assertEqual(sw, 0x9000)

    def test_oversized_response_returns_61_and_keeps_tail(self):
        body = bytes(range(40))
        chunk, leftover, sw = seos_iso7816_split_response(body, max_frame=16)
        self.assertEqual(chunk, body[:14])
        self.assertEqual(leftover, body[14:])
        self.assertEqual(sw, seos_iso7816_more_sw(len(leftover)))
        self.assertEqual(sw >> 8, 0x61)

    def test_get_response_continues_then_9000(self):
        leftover = bytes(range(20))
        chunk, rest, sw = seos_iso7816_continue(leftover, le=10, max_frame=32)
        self.assertEqual(chunk, leftover[:10])
        self.assertEqual(rest, leftover[10:])
        self.assertEqual(sw >> 8, 0x61)
        chunk, rest, sw = seos_iso7816_continue(rest, le=0, max_frame=32)
        self.assertEqual(chunk, leftover[10:])
        self.assertEqual(rest, b"")
        self.assertEqual(sw, 0x9000)

    def test_get_response_le_zero_means_256(self):
        leftover = bytes(range(40))
        chunk, rest, sw = seos_iso7816_continue(leftover, le=0, max_frame=20)
        self.assertEqual(len(chunk), 18)
        self.assertEqual(rest, leftover[18:])
        self.assertEqual(sw, seos_iso7816_more_sw(len(rest)))

    def test_more_sw_uses_zero_when_remaining_exceeds_255(self):
        self.assertEqual(seos_iso7816_more_sw(20), 0x6114)
        self.assertEqual(seos_iso7816_more_sw(256), 0x6100)

    def test_get_response_with_nothing_pending_is_empty(self):
        chunk, rest, sw = seos_iso7816_continue(b"", le=0, max_frame=32)
        self.assertEqual(chunk, b"")
        self.assertEqual(rest, b"")
        self.assertEqual(sw, 0x6A86)


class TestSeosMultiTag(unittest.TestCase):
    def test_tag_list_names_one(self):
        self.assertEqual(
            seos_parse_requested_tags(bytes.fromhex("5C02FF00")),
            [bytes.fromhex("FF00")],
        )

    def test_tag_list_rejects_two_tags(self):
        with self.assertRaises(ValueError):
            seos_parse_requested_tags(bytes.fromhex("5C04FF00FF41"))

    def test_extended_header_list_one_tag(self):
        self.assertEqual(
            seos_parse_requested_tags(bytes.fromhex("4D03FF0000")),
            [bytes.fromhex("FF00")],
        )

    def test_extended_header_list_many(self):
        self.assertEqual(
            seos_parse_requested_tags(bytes.fromhex("4D06FF4100FF0000")),
            [bytes.fromhex("FF41"), bytes.fromhex("FF00")],
        )

    def test_extended_header_list_needs_zero_lengths(self):
        with self.assertRaises(ValueError):
            seos_parse_requested_tags(bytes.fromhex("4D03FF0004"))
        with self.assertRaises(ValueError):
            seos_parse_requested_tags(bytes.fromhex("4D02FF00"))

    def test_unknown_tag_is_empty_success(self):
        store = [(bytes.fromhex("FF00"), bytes.fromhex("0500"))]
        self.assertEqual(seos_collect_objects(store, [bytes.fromhex("FF41")]), b"")

    def test_collect_concatenates_known_tags(self):
        store = [
            (bytes.fromhex("FF00"), bytes.fromhex("0500")),
            (bytes.fromhex("FF41"), bytes.fromhex("AABB")),
        ]
        blob = seos_collect_objects(
            store, [bytes.fromhex("FF41"), bytes.fromhex("FF00")]
        )
        self.assertEqual(blob, bytes.fromhex("FF4102AABBFF00020500"))

    def test_parse_object_arg(self):
        tag, value = seos_parse_object_arg("FF41:AABBCC")
        self.assertEqual(tag, bytes.fromhex("FF41"))
        self.assertEqual(value, bytes.fromhex("AABBCC"))

    def test_pack_unpack_extra_objects(self):
        extras = [(bytes.fromhex("FF41"), bytes.fromhex("DEAD"))]
        packed = pack_seos_emu_data(
            data=bytes.fromhex("0500"),
            oid=SEOS_FACTORY_ADF_OID,
            tag=bytes.fromhex("FF00"),
            diversifier=bytes.fromhex("01020304050607"),
            hash_alg=SEOS_HASH_SHA256,
            encr_alg=SEOS_ENCR_AES,
            gdf_oid=SEOS_FACTORY_GDF_OID,
            gdf_diversifier=SEOS_FACTORY_GDF_DIV,
            extras=extras,
        )
        parsed = unpack_seos_emu_data(packed)
        self.assertEqual(parsed["extras"], extras)

    def test_eview_prints_extra_objects(self):
        lines = format_seos_eview(
            {
                "data": bytes.fromhex("0500"),
                "oid": SEOS_FACTORY_ADF_OID,
                "tag": bytes.fromhex("FF00"),
                "diversifier": bytes.fromhex("01020304050607"),
                "hash_alg": SEOS_HASH_SHA256,
                "encr_alg": SEOS_ENCR_AES,
                "extras": [(bytes.fromhex("FF41"), bytes.fromhex("DEAD"))],
            }
        )
        text = "\n".join(lines)
        self.assertIn("Object: FF41 DEAD", text)


if __name__ == "__main__":
    unittest.main()
