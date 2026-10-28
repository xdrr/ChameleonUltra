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
    SEOS_MOBILE_ADMIN_AID,
    SEOS_HASH_SHA1,
    SEOS_HASH_SHA256,
    SEOS_KEYSLOT_WRITE,
    SEOS_SW_SM_INCORRECT,
    SEOS_SW_SM_MISSING,
    SEOS_ADP_STATIC_RND_ICC,
    add_seos_adf2_args,
    add_seos_gdf_args,
    add_seos_adf2_key_args,
    add_seos_rnd_arg,
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
    seos_ber_length,
    seos_collect_objects,
    seos_iblock_reassemble,
    seos_get_response_apdu,
    seos_iso7816_continue,
    seos_iso7816_leftover_retry,
    seos_round_to_next,
    seos_ins_needs_wtx,
    seos_pcb_is_wtx,
    seos_wtx_on_iblock,
    seos_wtx_on_sblock,
    seos_wtx_process_on_ack,
    SEOS_WTX_ECHO_WTX,
    SEOS_WTX_PROCESS,
    SEOS_WTX_SEND_IBLOCK,
    SEOS_WTX_SEND_WTX,
    SEOS_WTX_WAIT,
    seos_iso7816_more_sw,
    seos_iso7816_retry_le,
    seos_iso7816_split_response,
    seos_iso7816_wrong_le,
    seos_unwrap_get_data_rapdu,
    seos_wrap_get_data_capdu,
    seos_wrap_get_data_rapdu,
    seos_session_keys,
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


class TestSeosAdf2Keys(unittest.TestCase):
    def test_pack_unpack_distinct_adf2_keys(self):
        auth = bytes(range(16))
        privenc = bytes(range(16, 32))
        privmac = bytes(range(32, 48))
        write = bytes(range(48, 64))
        adf2_auth = bytes(range(64, 80))
        adf2_privenc = bytes(range(80, 96))
        adf2_privmac = bytes(range(96, 112))
        adf2_write = bytes(range(112, 128))
        packed = pack_seos_emu_keys(
            auth,
            privenc,
            privmac,
            write,
            adf2_auth=adf2_auth,
            adf2_privenc=adf2_privenc,
            adf2_privmac=adf2_privmac,
            adf2_auth_write=adf2_write,
        )
        self.assertEqual(len(packed), 128)
        parsed = unpack_seos_emu_keys(packed)
        self.assertEqual(parsed["auth"], auth)
        self.assertEqual(parsed["adf2_auth"], adf2_auth)
        self.assertEqual(parsed["adf2_privenc"], adf2_privenc)
        self.assertEqual(parsed["adf2_privmac"], adf2_privmac)
        self.assertEqual(parsed["adf2_auth_write"], adf2_write)
        self.assertNotEqual(parsed["adf2_auth"], parsed["auth"])

    def test_pack_adf2_keys_without_write_is_96(self):
        auth = bytes(range(16))
        privenc = bytes(range(16, 32))
        privmac = bytes(range(32, 48))
        adf2_auth = bytes(range(64, 80))
        packed = pack_seos_emu_keys(
            auth,
            privenc,
            privmac,
            adf2_auth=adf2_auth,
            adf2_privenc=bytes(range(80, 96)),
            adf2_privmac=bytes(range(96, 112)),
        )
        self.assertEqual(len(packed), 96)
        parsed = unpack_seos_emu_keys(packed)
        self.assertEqual(parsed["adf2_auth"], adf2_auth)
        self.assertNotIn("auth_write", parsed)
        self.assertNotIn("adf2_auth_write", parsed)

    def test_keys_parser_accepts_adf2_keys(self):
        import argparse

        parser = argparse.ArgumentParser()
        add_seos_adf2_key_args(parser)
        args = parser.parse_args(
            [
                "--adf2-auth",
                "00112233445566778899AABBCCDDEEFF",
                "--adf2-privenc",
                "112233445566778899AABBCCDDEEFF00",
                "--adf2-privmac",
                "2233445566778899AABBCCDDEEFF0011",
            ]
        )
        self.assertEqual(args.adf2_auth, "00112233445566778899AABBCCDDEEFF")
        self.assertEqual(args.adf2_privenc, "112233445566778899AABBCCDDEEFF00")
        self.assertEqual(args.adf2_privmac, "2233445566778899AABBCCDDEEFF0011")


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


class TestSeosBerLength(unittest.TestCase):
    def test_short_form_under_128(self):
        self.assertEqual(seos_ber_length(16), bytes([16]))
        self.assertEqual(seos_ber_length(127), bytes([127]))

    def test_long_form_for_large_cryptogram(self):
        self.assertEqual(seos_ber_length(224), bytes([0x81, 224]))
        self.assertEqual(seos_ber_length(255), bytes([0x81, 255]))
        self.assertEqual(seos_ber_length(272), bytes([0x82, 0x01, 0x10]))


class TestSeosSessionKeys(unittest.TestCase):
    def test_sha1_2k3des_matches_flipper_vector(self):
        enc, mac = seos_session_keys(
            key_ifd=bytes.fromhex("c7ced5dce3eaf1f8ff060d141b222930"),
            key_icc=bytes.fromhex("e7eef5fc030a11181f262d343b424950"),
            rnd_icc=bytes.fromhex("777e858c939aa1a8"),
            rnd_ifd=bytes.fromhex("a7aeb5bcc3cad1d8"),
            encr_alg=SEOS_ENCR_2K3DES,
            hash_alg=SEOS_HASH_SHA1,
        )
        self.assertEqual(enc, bytes.fromhex("ce1e7147b721cfa0ac5948b1e47c1725"))
        self.assertEqual(mac, bytes.fromhex("24eca46b64aa0d05f0d9d80f1f9d13f9"))


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
        chunk, rest, sw = seos_iso7816_continue(leftover, le=0, max_frame=16)
        self.assertEqual(chunk, leftover[:14])
        self.assertEqual(rest, leftover[14:])
        self.assertEqual(sw >> 8, 0x61)
        chunk, rest, sw = seos_iso7816_continue(rest, le=0, max_frame=32)
        self.assertEqual(chunk, leftover[14:])
        self.assertEqual(rest, b"")
        self.assertEqual(sw, 0x9000)

    def test_wrong_le_returns_6c_and_keeps_pending(self):
        leftover = bytes(range(20))
        chunk, rest, sw = seos_iso7816_continue(leftover, le=10, max_frame=32)
        self.assertEqual(chunk, b"")
        self.assertEqual(rest, leftover)
        self.assertEqual(sw, 0x6C14)

    def test_matching_le_is_not_wrong(self):
        leftover = bytes(range(20))
        chunk, rest, sw = seos_iso7816_continue(leftover, le=20, max_frame=32)
        self.assertEqual(chunk, leftover)
        self.assertEqual(rest, b"")
        self.assertEqual(sw, 0x9000)

    def test_wrong_le_helper(self):
        self.assertIsNone(seos_iso7816_wrong_le(20, 0))
        self.assertIsNone(seos_iso7816_wrong_le(20, 20))
        self.assertEqual(seos_iso7816_wrong_le(20, 10), 0x6C14)
        self.assertEqual(seos_iso7816_wrong_le(64, 8), 0x6C40)

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

    def test_wrong_le_retry_then_delivers_pending(self):
        leftover = bytes(range(20))
        self.assertEqual(seos_iso7816_retry_le(0x6C14), 20)
        self.assertIsNone(seos_iso7816_retry_le(0x9000))
        self.assertEqual(seos_get_response_apdu(10), bytes.fromhex("00C000000A"))
        chunk, rest, sw = seos_iso7816_leftover_retry(
            leftover, first_le=10, max_frame=32
        )
        self.assertEqual(chunk, leftover)
        self.assertEqual(rest, b"")
        self.assertEqual(sw, 0x9000)


class TestSeosRoundToNext(unittest.TestCase):
    def test_255_byte_object_pads_past_uint8(self):
        # tag(2)+len(1)+255 = 258, AES block 16 → 272, not a uint8 wrap
        self.assertEqual(seos_round_to_next(258, 16), 272)
        self.assertEqual(seos_round_to_next(258, 8), 264)

    def test_small_and_aligned_lengths(self):
        self.assertEqual(seos_round_to_next(5, 16), 16)
        self.assertEqual(seos_round_to_next(16, 16), 16)
        self.assertEqual(seos_round_to_next(0, 16), 0)


class TestSeosWtxDeferral(unittest.TestCase):
    def test_get_and_update_data_need_wtx(self):
        self.assertTrue(seos_ins_needs_wtx(0xCB))
        self.assertTrue(seos_ins_needs_wtx(0xDA))
        self.assertTrue(seos_ins_needs_wtx(0xDB))

    def test_fast_ins_do_not_need_wtx(self):
        for ins in (0xA4, 0xA5, 0x87, 0xC0):
            self.assertFalse(seos_ins_needs_wtx(ins), ins)

    def test_iblock_defers_slow_ins_and_processes_fast_ins(self):
        self.assertEqual(seos_wtx_on_iblock(0xCB), SEOS_WTX_SEND_WTX)
        self.assertEqual(seos_wtx_on_iblock(0xA4), SEOS_WTX_PROCESS)
        self.assertEqual(seos_wtx_on_iblock(0xC0), SEOS_WTX_PROCESS)

    def test_sblock_ack_does_not_run_crypto(self):
        self.assertFalse(seos_wtx_process_on_ack())
        self.assertEqual(
            seos_wtx_on_sblock(waiting_ack=True, response_ready=False),
            SEOS_WTX_WAIT,
        )

    def test_sblock_ack_sends_iblock_only_when_ready(self):
        self.assertEqual(
            seos_wtx_on_sblock(waiting_ack=True, response_ready=True),
            SEOS_WTX_SEND_IBLOCK,
        )
        self.assertEqual(
            seos_wtx_on_sblock(waiting_ack=True, response_ready=False),
            SEOS_WTX_WAIT,
        )
        self.assertEqual(
            seos_wtx_on_sblock(waiting_ack=False, response_ready=False),
            SEOS_WTX_ECHO_WTX,
        )

    def test_pcb_recognizes_wtx_with_and_without_cid(self):
        self.assertTrue(seos_pcb_is_wtx(0xF2))
        self.assertTrue(seos_pcb_is_wtx(0xFA))
        self.assertFalse(seos_pcb_is_wtx(0x02))
        self.assertFalse(seos_pcb_is_wtx(0x0A))


class TestSeosGetDataWrap(unittest.TestCase):
    def test_2k3des_get_data_wrap_roundtrip(self):
        enc, mac = seos_session_keys(
            key_ifd=bytes.fromhex("c7ced5dce3eaf1f8ff060d141b222930"),
            key_icc=bytes.fromhex("e7eef5fc030a11181f262d343b424950"),
            rnd_icc=bytes.fromhex("777e858c939aa1a8"),
            rnd_ifd=bytes.fromhex("a7aeb5bcc3cad1d8"),
            encr_alg=SEOS_ENCR_2K3DES,
            hash_alg=SEOS_HASH_SHA1,
        )
        plaintext = bytes.fromhex("FF00020500")
        wrapped = seos_wrap_get_data_rapdu(
            enc_key=enc,
            mac_key=mac,
            rnd_icc=bytes.fromhex("777e858c939aa1a8"),
            rnd_ifd=bytes.fromhex("a7aeb5bcc3cad1d8"),
            plaintext=plaintext,
            encr_alg=SEOS_ENCR_2K3DES,
        )
        self.assertEqual(wrapped[0], 0x85)
        self.assertEqual(wrapped[-10:-8], bytes.fromhex("8E08"))
        recovered = seos_unwrap_get_data_rapdu(
            enc_key=enc,
            mac_key=mac,
            rnd_icc=bytes.fromhex("777e858c939aa1a8"),
            rnd_ifd=bytes.fromhex("a7aeb5bcc3cad1d8"),
            body=wrapped,
            encr_alg=SEOS_ENCR_2K3DES,
        )
        self.assertEqual(recovered, plaintext)

    def test_2k3des_get_data_command_has_85_97_8e(self):
        enc, mac = seos_session_keys(
            key_ifd=bytes.fromhex("c7ced5dce3eaf1f8ff060d141b222930"),
            key_icc=bytes.fromhex("e7eef5fc030a11181f262d343b424950"),
            rnd_icc=bytes.fromhex("777e858c939aa1a8"),
            rnd_ifd=bytes.fromhex("a7aeb5bcc3cad1d8"),
            encr_alg=SEOS_ENCR_2K3DES,
            hash_alg=SEOS_HASH_SHA1,
        )
        apdu = seos_wrap_get_data_capdu(
            enc_key=enc,
            mac_key=mac,
            rnd_icc=bytes.fromhex("777e858c939aa1a8"),
            rnd_ifd=bytes.fromhex("a7aeb5bcc3cad1d8"),
            tag=bytes.fromhex("FF00"),
            encr_alg=SEOS_ENCR_2K3DES,
        )
        self.assertEqual(apdu[:4], bytes.fromhex("0CCB3FFF"))
        body = apdu[5:]
        objects, cmac = seos_sm_mac_objects(body)
        self.assertIsNotNone(cmac)
        self.assertEqual(len(cmac), 8)
        self.assertIn(bytes.fromhex("9700"), objects)
        self.assertEqual(objects[0], 0x85)


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


class TestSeosMultiAdf(unittest.TestCase):
    def test_mobile_admin_aid_is_public(self):
        self.assertEqual(SEOS_MOBILE_ADMIN_AID, bytes.fromhex("A000000382002D000101"))

    def test_pack_unpack_extra_aid_and_adf2(self):
        packed = pack_seos_emu_data(
            data=bytes.fromhex("0500"),
            oid=SEOS_FACTORY_ADF_OID,
            tag=bytes.fromhex("FF00"),
            diversifier=bytes.fromhex("01020304050607"),
            hash_alg=SEOS_HASH_SHA256,
            encr_alg=SEOS_ENCR_AES,
            gdf_oid=SEOS_FACTORY_GDF_OID,
            gdf_diversifier=SEOS_FACTORY_GDF_DIV,
            extra_aid=SEOS_MOBILE_ADMIN_AID,
            adf2_oid=bytes.fromhex("03010709AABBCC"),
            adf2_diversifier=bytes.fromhex("11223344556677"),
            adf2_tag=bytes.fromhex("FF00"),
            adf2_data=bytes.fromhex("AABB"),
        )
        parsed = unpack_seos_emu_data(packed)
        self.assertEqual(parsed["extra_aid"], SEOS_MOBILE_ADMIN_AID)
        self.assertEqual(parsed["adf2_oid"], bytes.fromhex("03010709AABBCC"))
        self.assertEqual(parsed["adf2_diversifier"], bytes.fromhex("11223344556677"))
        self.assertEqual(parsed["adf2_tag"], bytes.fromhex("FF00"))
        self.assertEqual(parsed["adf2_data"], bytes.fromhex("AABB"))

    def test_eview_prints_extra_aid_and_adf2(self):
        lines = format_seos_eview(
            {
                "data": bytes.fromhex("0500"),
                "oid": SEOS_FACTORY_ADF_OID,
                "tag": bytes.fromhex("FF00"),
                "diversifier": bytes.fromhex("01020304050607"),
                "hash_alg": SEOS_HASH_SHA256,
                "encr_alg": SEOS_ENCR_AES,
                "extra_aid": SEOS_MOBILE_ADMIN_AID,
                "adf2_oid": bytes.fromhex("03010709AABBCC"),
                "adf2_diversifier": bytes.fromhex("11223344556677"),
                "adf2_tag": bytes.fromhex("FF00"),
                "adf2_data": bytes.fromhex("AABB"),
            }
        )
        text = "\n".join(lines)
        self.assertIn("Extra AID: A000000382002D000101", text)
        self.assertIn("ADF2 OID: 03010709AABBCC", text)
        self.assertIn("ADF2 Data: AABB", text)

    def test_eload_parser_accepts_adf2_fields(self):
        import argparse

        parser = argparse.ArgumentParser()
        add_seos_adf2_args(parser)
        args = parser.parse_args(
            [
                "--aid",
                "A000000382002D000101",
                "--adf2-oid",
                "03010709AABBCC",
                "--adf2-div",
                "11223344556677",
                "--adf2-data",
                "AABB",
                "--adf2-tag",
                "FF00",
            ]
        )
        self.assertEqual(args.aid, "A000000382002D000101")
        self.assertEqual(args.adf2_oid, "03010709AABBCC")
        self.assertEqual(args.adf2_data, "AABB")


class TestSeosStaticRnd(unittest.TestCase):
    def test_adp_static_rnd_is_captured(self):
        self.assertEqual(SEOS_ADP_STATIC_RND_ICC, bytes.fromhex("0181E43801010201"))

    def test_pack_unpack_static_rnd(self):
        packed = pack_seos_emu_data(
            data=bytes.fromhex("0500"),
            oid=SEOS_FACTORY_ADF_OID,
            tag=bytes.fromhex("FF00"),
            diversifier=bytes.fromhex("01020304050607"),
            hash_alg=SEOS_HASH_SHA256,
            encr_alg=SEOS_ENCR_AES,
            gdf_oid=SEOS_FACTORY_GDF_OID,
            gdf_diversifier=SEOS_FACTORY_GDF_DIV,
            rnd_icc=SEOS_ADP_STATIC_RND_ICC,
        )
        parsed = unpack_seos_emu_data(packed)
        self.assertEqual(parsed["rnd_icc"], SEOS_ADP_STATIC_RND_ICC)

    def test_eview_prints_static_or_random_rnd(self):
        static_lines = format_seos_eview(
            {
                "data": bytes.fromhex("0500"),
                "oid": SEOS_FACTORY_ADF_OID,
                "tag": bytes.fromhex("FF00"),
                "diversifier": bytes.fromhex("01020304050607"),
                "hash_alg": SEOS_HASH_SHA256,
                "encr_alg": SEOS_ENCR_AES,
                "rnd_icc": SEOS_ADP_STATIC_RND_ICC,
            }
        )
        self.assertIn("RND.ICC: static 0181E43801010201", "\n".join(static_lines))
        random_lines = format_seos_eview(
            {
                "data": bytes.fromhex("0500"),
                "oid": SEOS_FACTORY_ADF_OID,
                "tag": bytes.fromhex("FF00"),
                "diversifier": bytes.fromhex("01020304050607"),
                "hash_alg": SEOS_HASH_SHA256,
                "encr_alg": SEOS_ENCR_AES,
            }
        )
        self.assertIn("RND.ICC: randomized per field", "\n".join(random_lines))

    def test_eload_parser_accepts_rnd_icc(self):
        import argparse

        parser = argparse.ArgumentParser()
        add_seos_rnd_arg(parser)
        args = parser.parse_args(["--rnd-icc", "0181E43801010201"])
        self.assertEqual(args.rnd_icc, "0181E43801010201")


if __name__ == "__main__":
    unittest.main()
