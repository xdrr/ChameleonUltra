/**
 * @file nfc_seos.c
 * @brief SEOS emulation for ChameleonUltra
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include "nfc_seos.h"
#include "nfc_14a_4.h"
#include "nfc_14a.h"
#include "tag_emulation.h"
#include "tag_persistence.h"
#include "fds_util.h"
#include "nrf_log.h"
#include "nrf_drv_rng.h"

#include <nrf_crypto_aes.h>
#include <nrf_crypto_hash.h>

// Only AES128/SHA256 are currently available. 3DES and SHA1 would have to be implemented in software.

#define SEOS_ENCRYPTION_2K3DES      0x02
#define SEOS_ENCRYPTION_3K3DES      0x03
#define SEOS_ENCRYPTION_AES         0x09

#define SEOS_HASHING_SHA1           0x06
#define SEOS_HASHING_SHA256         0x07

const uint8_t SEOS_AID[] = { 0xA0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01 };

static uint8_t block_size(uint8_t algorithm) {
    if (algorithm == SEOS_ENCRYPTION_AES) {
        return 16;
    } else if (algorithm == SEOS_ENCRYPTION_2K3DES) {
        return 8;
    } else if (algorithm == SEOS_ENCRYPTION_3K3DES) {
        return 8;
    } else {
        NRF_LOG_ERROR("Seos: Unknown Encryption Algorithm");
        return 0;
    }
}

static uint8_t round_to_next(uint8_t value, uint8_t step) {
    if (value % step == 0) {
        return value;
    } else {
        return value + step - (value % step);
    }
}

static nrf_crypto_aes_context_t nrf_aes_ctx;
static nrf_crypto_hash_context_t nrf_hash_ctx;

static uint8_t cryptogram_iv[16] = {0x00};
static bool generate_cryptogram(uint8_t *key, bool use_iv, uint8_t *input, size_t length, uint8_t *output, uint8_t algorithm) {
    if (!use_iv) {
        memset(cryptogram_iv, 0x00, 16);
    }

    if (algorithm == SEOS_ENCRYPTION_AES) {
        ret_code_t result = nrf_crypto_aes_crypt(
            &nrf_aes_ctx, &g_nrf_crypto_aes_cbc_128_info, NRF_CRYPTO_ENCRYPT,
            key, cryptogram_iv,
            input, length,
            output, &length
        );

        if (result != NRF_SUCCESS) {
            NRF_LOG_ERROR("Seos: Error decrypting cryptogram: %s", nrf_crypto_error_string_get(result));
            return false;
        }
    } else {
        NRF_LOG_ERROR("Seos: Unknown Encryption Algorithm");
        return false;
    }

    return true;
}

static bool decrypt_cryptogram(uint8_t *key, uint8_t *input, size_t length, uint8_t *output, uint8_t algorithm) {
    memset(cryptogram_iv, 0x00, 16);

    if (algorithm == SEOS_ENCRYPTION_AES) {
        ret_code_t result = nrf_crypto_aes_crypt(
            &nrf_aes_ctx, &g_nrf_crypto_aes_cbc_128_info, NRF_CRYPTO_DECRYPT,
            key, cryptogram_iv,
            input, length,
            output, &length
        );

        if (result != NRF_SUCCESS) {
            NRF_LOG_ERROR("Seos: Error decrypting cryptogram: %s", nrf_crypto_error_string_get(result));
            return false;
        }
    } else {
        NRF_LOG_ERROR("Seos: Unknown Encryption Algorithm");
        return false;
    }

    return true;
}

static bool generate_cmac(uint8_t *key, uint8_t *input, size_t length, uint8_t *output, uint8_t encryption_algorithm) {
    memset(cryptogram_iv, 0x00, 16);

    if (encryption_algorithm == SEOS_ENCRYPTION_AES) {
        size_t hash_size = NRF_CRYPTO_AES_BLOCK_SIZE;
        ret_code_t result = nrf_crypto_aes_crypt(
            &nrf_aes_ctx, &g_nrf_crypto_aes_cmac_128_info, NRF_CRYPTO_MAC_CALCULATE,
            key, cryptogram_iv,
            input, length,
            output, &hash_size
        );

        if (result != NRF_SUCCESS) {
            NRF_LOG_ERROR("Seos: Error generating CMAC: %s", nrf_crypto_error_string_get(result));
            return false;
        } else if (hash_size != 16) {
            NRF_LOG_ERROR("Seos: Incorrect CMAC output size: %d", hash_size);
            return false;
        }
    } else {
        NRF_LOG_ERROR("Seos: Unknown Encryption Algorithm");
        return false;
    }

    return true;
}

static void seos_kdf(bool forEncryption, uint8_t *masterKey, uint8_t keyslot, uint8_t *work_buffer,
                     uint8_t *adfOid, size_t adfoid_len, uint8_t *diversifier, uint8_t diversifier_len, uint8_t *out, int encryption_algorithm, int hash_algorithm) {

    // Encryption key      = 04
    // KEK Encryption key  = 05
    // MAC key             = 06
    // KEK MAC key         = 07

    uint8_t typeOfKey = 0x06;
    if (forEncryption == true) {
        typeOfKey = 0x04;
    }

    memset(work_buffer, 0x00, 16);
    work_buffer[11] = typeOfKey;
    work_buffer[14] = 0x80;
    work_buffer[15] = 0x01;
    work_buffer[16] = encryption_algorithm;
    work_buffer[17] = hash_algorithm;
    work_buffer[18] = keyslot;
    memcpy(work_buffer + 19, adfOid, adfoid_len);
    memcpy(work_buffer + 19 + adfoid_len, diversifier, diversifier_len);

    // This CMAC always uses AES, regardless of the main encryption algorithm in use.
    generate_cmac(masterKey, work_buffer, 19 + adfoid_len + diversifier_len, out, SEOS_ENCRYPTION_AES);
}

#define WORK_BUFFER_SIZE 0x200
static uint8_t work_buffer_a[WORK_BUFFER_SIZE];
static uint8_t work_buffer_b[WORK_BUFFER_SIZE];

/* ------------------------------------------------------------------ */
/*  Module state                                                        */
/* ------------------------------------------------------------------ */
static nfc_tag_seos_information_t *m_tag_information = NULL;

/* Shadow coll-res references into m_tag_information */
static nfc_tag_14a_coll_res_reference_t m_shadow_coll_res;

/* T=CL session state */
static nfc_tag_14a_4_tcl_state_t m_tcl_session_state;

// These values are determined at runtime
static uint8_t RND_ICC[8] = { 0x00 };
static uint8_t RND_IFD[8] = { 0x00 };
static uint8_t KEY_ICC[16] = { 0x00 };
static uint8_t KEY_IFD[16] = { 0x00 };
static uint8_t diver_encr_key[16] = { 0x00 };
static uint8_t diver_cmac_key[16] = { 0x00 };
static bool seos_sm_active = false;
static uint8_t seos_pending[NFC_14A_4_MAX_APDU];
static uint16_t seos_pending_len = 0;

#define SEOS_SW_SM_MISSING    0x6987
#define SEOS_SW_SM_INCORRECT  0x6988
#define SEOS_SW_WRONG_P1P2    0x6A86
#define SEOS_APDU_FRAME_MAX   NFC_14A_4_INF_MAX

static void seos_pending_clear(void) {
    seos_pending_len = 0;
}

/* Per-field anti-collision UID. 4-byte 08 RIDs are randomized so the
 * stored slot UID is not a static air-interface fingerprint. */
static uint8_t session_uid[10];

static void seos_rng_fill(uint8_t *buf, uint8_t len) {
    uint8_t got = 0;
    uint32_t guard = 0;
    while (got < len) {
        uint8_t avail = 0;
        nrf_drv_rng_bytes_available(&avail);
        if (avail > 0) {
            uint8_t want = (uint8_t)(len - got);
            uint8_t chunk = (avail < want) ? avail : want;
            if (nrf_drv_rng_rand(buf + got, chunk) == NRF_SUCCESS) {
                got += chunk;
                continue;
            }
        }
        if (++guard > 200000) {
            while (got < len) {
                buf[got++] = (uint8_t)rand();
            }
            break;
        }
    }
}

static void seos_refresh_session(void) {
    seos_rng_fill(RND_ICC, sizeof(RND_ICC));
    seos_rng_fill(KEY_ICC, sizeof(KEY_ICC));
    memset(RND_IFD, 0, sizeof(RND_IFD));
    memset(KEY_IFD, 0, sizeof(KEY_IFD));
    memset(diver_encr_key, 0, sizeof(diver_encr_key));
    memset(diver_cmac_key, 0, sizeof(diver_cmac_key));
    seos_sm_active = false;
    seos_pending_clear();

    if (m_tag_information == NULL) {
        return;
    }

    memcpy(session_uid, m_tag_information->res_coll.uid, sizeof(session_uid));
    if (m_tag_information->res_coll.size == NFC_TAG_14A_UID_SINGLE_SIZE &&
        session_uid[0] == 0x08) {
        seos_rng_fill(&session_uid[1], 3);
    }
}

static void seos_sm_fail(uint8_t *apdu_status, uint16_t sw) {
    /* ISO7816: missing/incorrect SM objects are answered in the clear and
     * end the session so the counters cannot be reused. */
    seos_sm_active = false;
    seos_pending_clear();
    memset(diver_encr_key, 0, sizeof(diver_encr_key));
    memset(diver_cmac_key, 0, sizeof(diver_cmac_key));
    m_tcl_session_state.m_resp_len = 0;
    apdu_status[0] = (uint8_t)(sw >> 8);
    apdu_status[1] = (uint8_t)(sw & 0xFF);
}

/* Send one ISO7816 APDU. If the body plus SW does not fit one T=CL
 * I-block, keep the tail for GET RESPONSE (00 C0) and return 61 xx. */
static void seos_commit_response(uint8_t *apdu_status) {
    uint16_t body_len = m_tcl_session_state.m_resp_len;
    uint16_t room = (SEOS_APDU_FRAME_MAX > 2) ? (uint16_t)(SEOS_APDU_FRAME_MAX - 2) : 0;

    if (body_len <= room) {
        m_tcl_session_state.m_resp_buf[body_len] = apdu_status[0];
        m_tcl_session_state.m_resp_buf[body_len + 1] = apdu_status[1];
        m_tcl_session_state.m_resp_len = body_len + 2;
    } else {
        uint16_t leftover = (uint16_t)(body_len - room);
        if (leftover > sizeof(seos_pending)) {
            leftover = sizeof(seos_pending);
        }
        memcpy(seos_pending, m_tcl_session_state.m_resp_buf + room, leftover);
        seos_pending_len = leftover;
        m_tcl_session_state.m_resp_buf[room] = 0x61;
        m_tcl_session_state.m_resp_buf[room + 1] = (leftover > 0xFF) ? 0x00 : (uint8_t)leftover;
        m_tcl_session_state.m_resp_len = room + 2;
    }

    m_tcl_session_state.m_response_ready = true;
    NRF_NFCT->FRAMEDELAYMAX = 135600; // 10ms
    nfc_tag_14a_4_base_respond(&m_tcl_session_state);
}

/* ------------------------------------------------------------------ */
/*  Anti-collision resource                                             */
/* ------------------------------------------------------------------ */

nfc_tag_14a_coll_res_reference_t *nfc_tag_seos_get_coll_res(void) {
    if (m_tag_information == NULL) return NULL;
    m_shadow_coll_res.sak  = m_tag_information->res_coll.sak;
    m_shadow_coll_res.atqa = m_tag_information->res_coll.atqa;
    m_shadow_coll_res.uid  = session_uid;
    m_shadow_coll_res.size = &m_tag_information->res_coll.size;
    m_shadow_coll_res.ats  = &m_tag_information->res_coll.ats;
    return &m_shadow_coll_res;
}

void seos_apply_factory_gdf(nfc_tag_seos_information_t *info) {
    /* Distinct from the Zero-Key ADF OID so GDF SELECT is not an ADF replay. */
    static const uint8_t DEFAULT_GDF_OID[] = {0x03, 0x01, 0x07, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const uint8_t DEFAULT_GDF_DIV[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memset(info->gdf_oid, 0, sizeof(info->gdf_oid));
    memset(info->gdf_diversifier, 0, sizeof(info->gdf_diversifier));
    info->gdf_oid_len = sizeof(DEFAULT_GDF_OID);
    memcpy(info->gdf_oid, DEFAULT_GDF_OID, info->gdf_oid_len);
    info->gdf_diversifier_len = sizeof(DEFAULT_GDF_DIV);
    memcpy(info->gdf_diversifier, DEFAULT_GDF_DIV, info->gdf_diversifier_len);
    info->gdf_magic = SEOS_GDF_LAYOUT_MAGIC;
}

bool seos_gdf_record_valid(const nfc_tag_seos_information_t *info) {
    return info->gdf_magic == SEOS_GDF_LAYOUT_MAGIC &&
           info->gdf_oid_len > 0 && info->gdf_oid_len <= NFC_TAG_SEOS_OID_MAX &&
           info->gdf_diversifier_len > 0 && info->gdf_diversifier_len <= NFC_TAG_SEOS_DIVERSIFIER_MAX;
}

void seos_apply_default_writekey(nfc_tag_seos_information_t *info) {
    memcpy(info->authkey_write, info->authkey, 16);
    info->writekey_magic = SEOS_WRITEKEY_MAGIC;
}

bool seos_writekey_valid(const nfc_tag_seos_information_t *info) {
    return info->writekey_magic == SEOS_WRITEKEY_MAGIC;
}

void seos_apply_empty_objects(nfc_tag_seos_information_t *info) {
    info->objects_magic = SEOS_OBJECTS_MAGIC;
    info->extra_count = 0;
    memset(info->extra, 0, sizeof(info->extra));
}

bool seos_objects_valid(const nfc_tag_seos_information_t *info) {
    return info->objects_magic == SEOS_OBJECTS_MAGIC &&
           info->extra_count <= NFC_TAG_SEOS_EXTRA_MAX;
}

static bool seos_tag_eq(const uint8_t *a, uint8_t a_len, const uint8_t *b, uint8_t b_len) {
    return a_len == b_len && a_len > 0 && memcmp(a, b, a_len) == 0;
}

static bool seos_find_object(const nfc_tag_seos_information_t *info,
                             const uint8_t *tag, uint8_t tag_len,
                             const uint8_t **data_out, uint8_t *data_len_out) {
    if (seos_tag_eq(info->data_tag, info->data_tag_len, tag, tag_len)) {
        *data_out = info->data;
        *data_len_out = info->data_len;
        return true;
    }
    for (uint8_t i = 0; i < info->extra_count && i < NFC_TAG_SEOS_EXTRA_MAX; i++) {
        if (seos_tag_eq(info->extra[i].tag, info->extra[i].tag_len, tag, tag_len)) {
            *data_out = info->extra[i].data;
            *data_len_out = info->extra[i].data_len;
            return true;
        }
    }
    return false;
}

static bool seos_store_named_object(nfc_tag_seos_information_t *info,
                                    const uint8_t *tag, uint8_t tag_len,
                                    const uint8_t *value, uint8_t value_len) {
    if (tag_len == 0 || tag_len > NFC_TAG_SEOS_DATA_TAG_MAX ||
        value_len == 0 || value_len > NFC_TAG_SEOS_DATA_MAX) {
        return false;
    }
    if (seos_tag_eq(info->data_tag, info->data_tag_len, tag, tag_len) ||
        info->data_tag_len == 0) {
        memcpy(info->data_tag, tag, tag_len);
        info->data_tag_len = tag_len;
        memcpy(info->data, value, value_len);
        info->data_len = value_len;
        return true;
    }
    for (uint8_t i = 0; i < info->extra_count && i < NFC_TAG_SEOS_EXTRA_MAX; i++) {
        if (seos_tag_eq(info->extra[i].tag, info->extra[i].tag_len, tag, tag_len)) {
            memcpy(info->extra[i].data, value, value_len);
            info->extra[i].data_len = value_len;
            return true;
        }
    }
    if (info->extra_count >= NFC_TAG_SEOS_EXTRA_MAX) {
        return false;
    }
    uint8_t idx = info->extra_count;
    memcpy(info->extra[idx].tag, tag, tag_len);
    info->extra[idx].tag_len = tag_len;
    memcpy(info->extra[idx].data, value, value_len);
    info->extra[idx].data_len = value_len;
    info->extra_count++;
    info->objects_magic = SEOS_OBJECTS_MAGIC;
    return true;
}

static bool seos_read_ber_tag(const uint8_t *data, uint16_t end, uint16_t *offset,
                              uint8_t *tag, uint8_t *tag_len) {
    if (*offset >= end) {
        return false;
    }
    if ((data[*offset] & 0x1F) == 0x1F) {
        if ((uint16_t)(*offset + 1) >= end) {
            return false;
        }
        tag[0] = data[*offset];
        tag[1] = data[*offset + 1];
        *tag_len = 2;
        *offset = (uint16_t)(*offset + 2);
        return true;
    }
    tag[0] = data[*offset];
    *tag_len = 1;
    *offset = (uint16_t)(*offset + 1);
    return true;
}

#define SEOS_MAX_REQUESTED_TAGS 4

static bool seos_parse_requested_tags(const uint8_t *data, uint16_t data_len,
                                      uint8_t tags[][NFC_TAG_SEOS_DATA_TAG_MAX],
                                      uint8_t *tag_lens, uint8_t *tag_count) {
    if (data_len < 3 || (data[0] != 0x5C && data[0] != 0x4D)) {
        return false;
    }
    uint8_t body_len = data[1];
    if (body_len == 0 || data_len < (uint16_t)(2 + body_len)) {
        return false;
    }
    uint16_t end = (uint16_t)(2 + body_len);
    uint16_t offset = 2;
    *tag_count = 0;
    while (offset < end) {
        if (*tag_count >= SEOS_MAX_REQUESTED_TAGS) {
            return false;
        }
        if (!seos_read_ber_tag(data, end, &offset, tags[*tag_count], &tag_lens[*tag_count])) {
            return false;
        }
        if (data[0] == 0x4D) {
            if (offset >= end || data[offset] != 0x00) {
                return false;
            }
            offset++;
        }
        (*tag_count)++;
    }
    if (data[0] == 0x5C && *tag_count != 1) {
        return false;
    }
    return *tag_count > 0;
}

const uint8_t *seos_auth_master_for_keyslot(const nfc_tag_seos_information_t *info, uint8_t keyslot) {
    if (keyslot == SEOS_KEYSLOT_WRITE) {
        return info->authkey_write;
    }
    return info->authkey;
}

/* Public SELECT DF reply used by both ADF and GDF: CD (algs) + 85 (IV||cryptogram) + 8E (CMAC).
 * Plaintext inside the cryptogram is OID 0x06 and diversifier 0xCF. */
static bool seos_fill_select_df_response(uint8_t *apdu_status,
                                         const uint8_t *oid, uint8_t oid_len,
                                         const uint8_t *diversifier, uint8_t diversifier_len) {
    const uint8_t bs = block_size(m_tag_information->encr_alg);
    const uint8_t half_bs = bs >> 1;

    uint8_t iv_rand[16];
    seos_rng_fill(iv_rand, half_bs);
    if (!generate_cmac(m_tag_information->privmac, iv_rand, half_bs, work_buffer_a, m_tag_information->encr_alg)) {
        NRF_LOG_ERROR("Seos: Select DF failed: Failed to create IV CMAC.");
        return false;
    }
    memcpy(cryptogram_iv, iv_rand, half_bs);
    memcpy(cryptogram_iv + half_bs, work_buffer_a, half_bs);

    const uint8_t reply_len = 0x30;
    uint8_t reply_idx = 0;
    uint8_t *reply = work_buffer_a;
    memset(reply, 0, reply_len);

    reply[reply_idx++] = 0x06;
    reply[reply_idx++] = oid_len;
    memcpy(reply + reply_idx, oid, oid_len);
    reply_idx += oid_len;

    reply[reply_idx++] = 0xCF;
    reply[reply_idx++] = diversifier_len;
    memcpy(reply + reply_idx, diversifier, diversifier_len);
    reply_idx += diversifier_len;

    if (6 + bs + reply_len + 10 > NFC_14A_4_MAX_APDU) {
        NRF_LOG_ERROR("Seos: Select DF failed: Response too large for buffer.");
        return false;
    }

    uint16_t tlv_idx = 0;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0xCD;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x02;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = m_tag_information->encr_alg;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = m_tag_information->hash_alg;

    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x85;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = reply_len + bs;
    memcpy(m_tcl_session_state.m_resp_buf + tlv_idx, cryptogram_iv, bs);
    tlv_idx += bs;

    if (!generate_cryptogram(m_tag_information->privenc, true, reply, reply_len, m_tcl_session_state.m_resp_buf + tlv_idx, m_tag_information->encr_alg)) {
        NRF_LOG_ERROR("Seos: Select DF failed: Failed to create reply cryptogram.");
        return false;
    }
    tlv_idx += reply_len;

    const uint8_t cmac_size = 8;
    uint8_t *cmac = work_buffer_a;
    if (!generate_cmac(m_tag_information->privmac, m_tcl_session_state.m_resp_buf, tlv_idx, cmac, m_tag_information->encr_alg)) {
        NRF_LOG_ERROR("Seos: Select DF failed: Failed to create reply CMAC.");
        return false;
    }

    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x8E;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = cmac_size;
    memcpy(m_tcl_session_state.m_resp_buf + tlv_idx, cmac, cmac_size);
    tlv_idx += cmac_size;

    m_tcl_session_state.m_resp_len = tlv_idx;
    apdu_status[0] = 0x90;
    apdu_status[1] = 0x00;
    return true;
}

/* Flipper-style privacy shill: well-formed success so unmatched ADF / failed
 * GA2 do not leak 6A82 (file not found) to an unauthorized reader. */
#define SEOS_SHILL_SELECT_CRYPTOGRAM_LEN  0x40
#define SEOS_SHILL_SELECT_CMAC_LEN        0x08
#define SEOS_SHILL_AUTH_BODY_LEN          0x28

static void seos_fill_shill_select_adf(uint8_t *apdu_status) {
    uint16_t tlv_idx = 0;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0xCD;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x02;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = m_tag_information->encr_alg;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = m_tag_information->hash_alg;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x85;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = SEOS_SHILL_SELECT_CRYPTOGRAM_LEN;
    seos_rng_fill(m_tcl_session_state.m_resp_buf + tlv_idx, SEOS_SHILL_SELECT_CRYPTOGRAM_LEN);
    tlv_idx += SEOS_SHILL_SELECT_CRYPTOGRAM_LEN;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x8E;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = SEOS_SHILL_SELECT_CMAC_LEN;
    seos_rng_fill(m_tcl_session_state.m_resp_buf + tlv_idx, SEOS_SHILL_SELECT_CMAC_LEN);
    tlv_idx += SEOS_SHILL_SELECT_CMAC_LEN;
    m_tcl_session_state.m_resp_len = tlv_idx;
    apdu_status[0] = 0x90;
    apdu_status[1] = 0x00;
}

static void seos_fill_shill_authenticate(uint8_t *apdu_status) {
    uint16_t tlv_idx = 0;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x7C;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = SEOS_SHILL_AUTH_BODY_LEN + 2;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x82;
    m_tcl_session_state.m_resp_buf[tlv_idx++] = SEOS_SHILL_AUTH_BODY_LEN;
    seos_rng_fill(m_tcl_session_state.m_resp_buf + tlv_idx, SEOS_SHILL_AUTH_BODY_LEN);
    tlv_idx += SEOS_SHILL_AUTH_BODY_LEN;
    m_tcl_session_state.m_resp_len = tlv_idx;
    apdu_status[0] = 0x90;
    apdu_status[1] = 0x00;
}

/* ------------------------------------------------------------------ */
/*  State handler (called from NFCT ISR on each received frame)        */
/* ------------------------------------------------------------------ */

static void nfc_tag_seos_state_handler(uint8_t *data, uint16_t szBytes) {
    // Only continue if we have a full APDU ready
    if (!nfc_tag_14a_4_base_handler(&m_tcl_session_state, data, szBytes)) return;

    uint8_t *receivedCmd = m_tcl_session_state.m_apdu_buf;
    m_tcl_session_state.m_resp_len = 0;

    uint8_t apdu_status[2] = {0x6A, 0x82}; // Default: Not Found

    // Calculated block size
    const uint8_t bs = block_size(m_tag_information->encr_alg);
    const uint8_t half_bs = bs >> 1;

    NRF_LOG_DEBUG("Seos: INS %02X CLA %02X P1 %02X P2 %02X", receivedCmd[0], receivedCmd[1], receivedCmd[2], receivedCmd[3]);

    switch (receivedCmd[1]) { // APDU Class Byte
        case 0xA4: {  // SELECT FILE
            // Select File AID uses the following format for GlobalPlatform
            //
            // | 00 | A4 | 04 | 00 | xx | AID | 00 |
            // xx in this case is len of the AID value in hex

            // aid len is found as a hex value in receivedCmd[6] (Index Starts at 0)
            uint8_t aid_len = receivedCmd[4];
            uint8_t *aid = &receivedCmd[5];

            if ((aid_len == sizeof(SEOS_AID)) && (memcmp(SEOS_AID, aid, sizeof(SEOS_AID)) == 0)) { // Evaluate the AID sent by the Reader to the AID supplied
                // Format as TLV and acknowledge
                /*
                6F 0C
                    84 0A
                    A0000004400001010001
                90 00
                */

                m_tcl_session_state.m_resp_buf[0] = 0x6F; // Tag
                m_tcl_session_state.m_resp_buf[1] = aid_len + 2; // Length
                m_tcl_session_state.m_resp_buf[2] = 0x84; // Inner Tag
                m_tcl_session_state.m_resp_buf[3] = aid_len; // Inner Length
                memcpy(m_tcl_session_state.m_resp_buf + 4, aid, aid_len);
                m_tcl_session_state.m_resp_len = 4 + aid_len;

                // Set status code to Success
                apdu_status[0] = 0x90;
                apdu_status[1] = 0x00;
            } // Any other SELECT FILE command will return with a Not Found
        }
        break;

        case 0xA5: {  // SELECT OID / Global DF
            // GDF is 00 A5 07 .. with no ADF TLV. Same public SELECT DF
            // cryptogram as ADF (CD / 85 / 8E) using the configured OID.
            if (receivedCmd[2] == 0x07) {
                if (!seos_gdf_record_valid(m_tag_information)) {
                    seos_apply_factory_gdf(m_tag_information);
                }
                seos_fill_select_df_response(apdu_status,
                                             m_tag_information->gdf_oid, m_tag_information->gdf_oid_len,
                                             m_tag_information->gdf_diversifier, m_tag_information->gdf_diversifier_len);
                break;
            }

            if (receivedCmd[4] == 0x00) {
                apdu_status[0] = 0x6A;
                apdu_status[1] = 0x81;
                break;
            }

            uint8_t received_tlv_len = receivedCmd[4];
            uint8_t *received_tlv = &receivedCmd[5];

            bool selected_oid = false;

            uint8_t tlv_offset = 0;
            while (tlv_offset + 2 <= received_tlv_len) {

                uint8_t tag = received_tlv[tlv_offset++];

                uint8_t length = received_tlv[tlv_offset++];

                NRF_LOG_DEBUG("Seos: Checking OID @ off=%d, T=%02X L=%d", tlv_offset, tag, length);

                if (length > received_tlv_len - tlv_offset) {
                    break;
                }

                uint8_t *value = &received_tlv[tlv_offset];
                if (tag == 0x06) {
                    if (length == m_tag_information->oid_len && memcmp(value, m_tag_information->oid, length) == 0) {
                        selected_oid = true;
                        break;
                    }
                }
                tlv_offset += length;
            }
            NRF_LOG_DEBUG("Seos: Selected OID? %d", selected_oid);

            if (selected_oid) {
                seos_fill_select_df_response(apdu_status,
                                             m_tag_information->oid, m_tag_information->oid_len,
                                             m_tag_information->diversifier, m_tag_information->diversifier_len);
            } else {
                seos_fill_shill_select_adf(apdu_status);
            }
        }
        break;

        case 0x87: {  // MUTUAL AUTH
            // This is specific to Seos
            // Should be a TLV structure with the OID stored in tag 0x16
            uint8_t *received_tlv = &receivedCmd[5];

            if (received_tlv[0] != 0x7C) {
                NRF_LOG_ERROR("Seos: Mutual auth failed: Invalid tag, expected 7C, got %02X", received_tlv[0]);
                break;
            }

            received_tlv += 2;

            if (received_tlv[0] == 0x81) {
                // Request for RND.ICC
                uint8_t tlv_idx = 0;

                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x7C; // Tag: mutual auth
                m_tcl_session_state.m_resp_buf[tlv_idx++] = sizeof(RND_ICC) + 2; // Length
                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x81; // Tag: request for RND.ICC
                m_tcl_session_state.m_resp_buf[tlv_idx++] = sizeof(RND_ICC); // Length
                memcpy(m_tcl_session_state.m_resp_buf + tlv_idx, RND_ICC, sizeof(RND_ICC));
                tlv_idx += sizeof(RND_ICC);

                m_tcl_session_state.m_resp_len = tlv_idx;

                // Set status code to Success
                apdu_status[0] = 0x90;
                apdu_status[1] = 0x00;
            } else if (received_tlv[0] == 0x82) {
                // Request for challenge
                uint8_t received_tlv_len = received_tlv[1];
                received_tlv += 2;

                if (received_tlv_len > WORK_BUFFER_SIZE) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Recieved cryptogram too long.");
                    break;
                }

                if (received_tlv_len < 32) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Recieved cryptogram too short.");
                    break;
                }

                uint8_t keyslot = receivedCmd[3]; // APDU P2 byte
                const uint8_t *auth_master = seos_auth_master_for_keyslot(m_tag_information, keyslot);

                seos_kdf(true, (uint8_t *)auth_master, keyslot, work_buffer_a, m_tag_information->oid, m_tag_information->oid_len, m_tag_information->diversifier, m_tag_information->diversifier_len, diver_encr_key, m_tag_information->encr_alg, m_tag_information->hash_alg);
                seos_kdf(false, (uint8_t *)auth_master, keyslot, work_buffer_a, m_tag_information->oid, m_tag_information->oid_len, m_tag_information->diversifier, m_tag_information->diversifier_len, diver_cmac_key, m_tag_information->encr_alg, m_tag_information->hash_alg);

                // Verify CMAC (last 8 bytes)
                uint8_t request_len = received_tlv_len - 8;
                uint8_t *cmac = work_buffer_a;
                if (!generate_cmac(diver_cmac_key, received_tlv, request_len, cmac, m_tag_information->encr_alg)) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Failed to create CMAC.");
                    break;
                }
                if (memcmp(cmac, received_tlv + request_len, 8) != 0) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Invalid CMAC.");
                    break;
                }

                memset(work_buffer_a, 0xDD, WORK_BUFFER_SIZE);

                uint8_t *request = work_buffer_a;
                if (!decrypt_cryptogram(diver_encr_key, received_tlv, request_len, request, m_tag_information->encr_alg)) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Failed to decrypt cryptogram.");
                    break;
                }

                // request = RND.IFD | RND.ICC | Key.IFD
                if (memcmp(RND_ICC, request + 8, 8) != 0) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Incorrect RND.ICC.");
                    break;
                }
                memcpy(RND_IFD, request, 8);
                memcpy(KEY_IFD, request + 16, 16);

                // reply = RND_ICC | RND_IFD | KEY_ICC
                const uint8_t reply_plain_len = 32;
                uint8_t *reply_plain = work_buffer_a;
                memcpy(reply_plain + 0, RND_ICC, 8);
                memcpy(reply_plain + 8, RND_IFD, 8);
                memcpy(reply_plain + 16, KEY_ICC, 16);

                // Generate cryptogram + 8-byte CMAC
                const uint8_t reply_len = reply_plain_len + 8;
                uint8_t *reply = work_buffer_b;
                generate_cryptogram(diver_encr_key, false, reply_plain, reply_plain_len, reply, m_tag_information->encr_alg);
                if (!generate_cmac(diver_cmac_key, reply, reply_plain_len, reply + reply_plain_len, m_tag_information->encr_alg)) {
                    NRF_LOG_ERROR("Seos: Mutual auth failed: Failed to create reply CMAC.");
                    break;
                }

                uint8_t tlv_idx = 0;

                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x7C; // Tag: mutual auth
                m_tcl_session_state.m_resp_buf[tlv_idx++] = reply_len + 2; // Length
                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x82; // Tag: request for challenge
                m_tcl_session_state.m_resp_buf[tlv_idx++] = reply_len; // Length
                memcpy(m_tcl_session_state.m_resp_buf + tlv_idx, reply, reply_len);
                tlv_idx += reply_len;

                m_tcl_session_state.m_resp_len = tlv_idx;

                // Set status code to Success
                apdu_status[0] = 0x90;
                apdu_status[1] = 0x00;

                // IMPORTANT: before sending reply, calculate final diversified keys

                uint8_t *hash_input = work_buffer_a;
                uint8_t hash_idx = 0;
                // Counter
                hash_input[hash_idx++] = 0x00;
                hash_input[hash_idx++] = 0x00;
                hash_input[hash_idx++] = 0x00;
                hash_input[hash_idx++] = 0x01;
                // Only copy first 8 bytes of each KEY
                memcpy(hash_input + hash_idx, KEY_IFD, 8);
                hash_idx += 8;
                memcpy(hash_input + hash_idx, KEY_ICC, 8);
                hash_idx += 8;
                // Yes, this is supposed to be the same thing twice
                hash_input[hash_idx++] = m_tag_information->encr_alg;
                hash_input[hash_idx++] = m_tag_information->encr_alg;
                // Copy full RND values
                memcpy(hash_input + hash_idx, RND_ICC, 8);
                hash_idx += 8;
                memcpy(hash_input + hash_idx, RND_IFD, 8);
                hash_idx += 8;

                uint8_t *hash_output = work_buffer_b;
                if (m_tag_information->hash_alg == SEOS_HASHING_SHA256) {
                    size_t hash_size = 32;
                    ret_code_t result = nrf_crypto_hash_calculate(&nrf_hash_ctx,
                        &g_nrf_crypto_hash_sha256_info,
                        hash_input, hash_idx, hash_output, &hash_size
                    );

                    if (result != NRF_SUCCESS) {
                        NRF_LOG_ERROR("Seos: Error generating SHA256 hash: %s", nrf_crypto_error_string_get(result));
                        break;
                    } else if (hash_size != 32) {
                        NRF_LOG_ERROR("Seos: Incorrect SHA256 output size: %d", hash_size);
                        break;
                    }
                } else {
                    NRF_LOG_ERROR("Seos: Unknown Hashing Algorithm");
                    break;
                }

                memcpy(diver_encr_key, hash_output, 16);
                memcpy(diver_cmac_key, hash_output + 16, 16);
                seos_sm_active = true;
            } else {
                NRF_LOG_ERROR("Seos: Mutual auth failed: Incorrect tag %02X found.", received_tlv[0]);
            }

            if (apdu_status[0] != 0x90) {
                seos_fill_shill_authenticate(apdu_status);
            }
        }
        break;

        case 0xC0: { // GET RESPONSE
            if (receivedCmd[2] != 0x00 || receivedCmd[3] != 0x00) {
                break;
            }
            if (seos_pending_len == 0) {
                if (!seos_sm_active) {
                    seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                } else {
                    apdu_status[0] = (uint8_t)(SEOS_SW_WRONG_P1P2 >> 8);
                    apdu_status[1] = (uint8_t)(SEOS_SW_WRONG_P1P2 & 0xFF);
                }
                break;
            }
            uint8_t le = 0;
            if (m_tcl_session_state.m_apdu_len >= 5) {
                le = receivedCmd[4];
            }
            uint16_t asked = (le == 0) ? 256 : le;
            uint16_t room = (SEOS_APDU_FRAME_MAX > 2) ? (uint16_t)(SEOS_APDU_FRAME_MAX - 2) : 0;
            if (room > asked) {
                room = asked;
            }
            if (room > seos_pending_len) {
                room = seos_pending_len;
            }
            memcpy(m_tcl_session_state.m_resp_buf, seos_pending, room);
            if (seos_pending_len > room) {
                memmove(seos_pending, seos_pending + room, seos_pending_len - room);
                seos_pending_len = (uint16_t)(seos_pending_len - room);
            } else {
                seos_pending_len = 0;
            }
            m_tcl_session_state.m_resp_len = room;
            if (seos_pending_len > 0) {
                apdu_status[0] = 0x61;
                apdu_status[1] = (seos_pending_len > 0xFF) ? 0x00 : (uint8_t)seos_pending_len;
            } else {
                apdu_status[0] = 0x90;
                apdu_status[1] = 0x00;
            }
        }
        break;

        case 0xDA:   // PUT DATA (PM3 emulator alias)
        case 0xDB:   // UPDATE DATA
        case 0xCB: { // GET DATA
            bool is_put = (receivedCmd[1] == 0xDA || receivedCmd[1] == 0xDB);
            seos_pending_clear();

            uint8_t received_tlv_len = receivedCmd[4];
            uint8_t *received_tlv = &receivedCmd[5];

            uint8_t *cryptogram = NULL;
            uint8_t *recvd_cmac = NULL;
            uint8_t cryptogram_length = 0;
            uint8_t recvd_cmac_length = 0;
            uint8_t recvd_cmac_offset = 0;
            bool has_protected_le = false;

            if (!seos_sm_active) {
                seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                break;
            }

            // Extract cryptogram, protected Le (97), and CMAC (8E).
            // The command MAC covers every DO before 8E, including 97.
            uint8_t tlv_offset = 0;
            while (tlv_offset + 2 <= received_tlv_len) {

                uint8_t tag_offset = tlv_offset;
                uint8_t tag = received_tlv[tlv_offset++];

                uint8_t length = received_tlv[tlv_offset++];
                if ((length & 0x80) == 0x80) {
                    // Multi-byte length
                    length &= 0x7F;
                    if (length != 1) {
                        NRF_LOG_ERROR("Seos: TLV element too long");
                        seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                        break;
                    }

                    // Grab that one extra byte
                    length = received_tlv[tlv_offset++];
                }

                if (length > received_tlv_len - tlv_offset) {
                    seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                    break;
                }

                uint8_t *value = &received_tlv[tlv_offset];

                if (tag == 0x85) {
                    cryptogram = value;
                    cryptogram_length = length;
                } else if (tag == 0x97) {
                    has_protected_le = true;
                    (void)value;
                } else if (tag == 0x8e) {
                    recvd_cmac = value;
                    recvd_cmac_length = length;
                    recvd_cmac_offset = tag_offset;
                }

                tlv_offset += length;
            }

            (void)has_protected_le;

            if (apdu_status[0] == 0x69) {
                break;
            }

            if (recvd_cmac == NULL || cryptogram == NULL) {
                NRF_LOG_ERROR("Seos: Get Data failed: Missing SM data object.");
                seos_sm_fail(apdu_status, SEOS_SW_SM_MISSING);
                break;
            }

            if (cryptogram != NULL && recvd_cmac != NULL) {
                if (cryptogram_length > WORK_BUFFER_SIZE) {
                    NRF_LOG_ERROR("Seos: Get Data failed: Recieved cryptogram too long.");
                    seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                    break;
                }

                // Combine the first half_bs each of RND_ICC and RND_IFD,
                //  then increment as a single counter
                uint8_t rndCounter[bs];
                memcpy(rndCounter, RND_ICC, half_bs);
                memcpy(rndCounter + half_bs, RND_IFD, half_bs);

                // skip zero bytes
                for (int8_t i = bs - 1; i >= 0; i--) {
                    rndCounter[i]++;

                    if (rndCounter[i]) {
                        break;
                    }
                }

                uint8_t *mac_input = work_buffer_a;
                uint16_t mac_input_idx = 0;

                // Add RND_* counter to mac_input
                memcpy(mac_input + mac_input_idx, rndCounter, bs);
                mac_input_idx += bs;

                // Add padded APDU header to mac_input
                uint8_t *padded_apdu_header = mac_input + mac_input_idx;
                memset(padded_apdu_header, 0, bs);
                memcpy(padded_apdu_header, receivedCmd, 4);
                padded_apdu_header[4] = 0x80;
                mac_input_idx += bs;

                // Add received TLV data to mac_input
                if (mac_input_idx + recvd_cmac_offset + bs > WORK_BUFFER_SIZE) {
                    NRF_LOG_ERROR("Seos: Get Data failed: CMAC input too large.");
                    seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                    break;
                }
                /* Includes 85 and protected Le (97) when the reader sent them. */
                memcpy(mac_input + mac_input_idx, received_tlv, recvd_cmac_offset);
                mac_input_idx += recvd_cmac_offset;

                // Add padding (if needed) to mac_input
                if (mac_input_idx % bs) {
                    memset(mac_input + mac_input_idx, 0, bs - (mac_input_idx % bs));
                    mac_input[mac_input_idx] = 0x80;
                    mac_input_idx += bs - (mac_input_idx % bs);
                }

                uint8_t *cmac = work_buffer_b;
                if (!generate_cmac(diver_cmac_key, mac_input, mac_input_idx, cmac, m_tag_information->encr_alg)) {
                    NRF_LOG_ERROR("Seos: Get Data failed: Failed to create CMAC.");
                    seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                    break;
                }
                if (memcmp(cmac, recvd_cmac, recvd_cmac_length) != 0) {
                    NRF_LOG_ERROR("Seos: Get Data failed: Invalid CMAC.");
                    seos_sm_fail(apdu_status, SEOS_SW_SM_INCORRECT);
                    break;
                }

                uint8_t *request = work_buffer_a;
                decrypt_cryptogram(diver_encr_key, cryptogram, cryptogram_length, request, m_tag_information->encr_alg);

                uint16_t tlv_idx = 0;

                if (is_put) {
                    /* PM3 sends tag||len||value when -t is set, or len||value
                     * when the tag defaults to empty and we keep the stored tag. */
                    uint8_t obj_tag[NFC_TAG_SEOS_DATA_TAG_MAX];
                    uint8_t obj_tag_len = 0;
                    const uint8_t *obj_val = NULL;
                    uint8_t obj_len = 0;
                    bool parsed = false;
                    if (cryptogram_length >= 3) {
                        uint8_t length = request[2];
                        if (length > 0 && length <= NFC_TAG_SEOS_DATA_MAX &&
                            (uint16_t)(3 + length) <= cryptogram_length) {
                            memcpy(obj_tag, request, 2);
                            obj_tag_len = 2;
                            obj_val = request + 3;
                            obj_len = length;
                            parsed = true;
                        }
                    }
                    if (!parsed && cryptogram_length >= 1) {
                        uint8_t length = request[0];
                        if (length > 0 && length <= NFC_TAG_SEOS_DATA_MAX &&
                            (uint16_t)(1 + length) <= cryptogram_length) {
                            if (m_tag_information->data_tag_len > 0 &&
                                m_tag_information->data_tag_len <= NFC_TAG_SEOS_DATA_TAG_MAX) {
                                memcpy(obj_tag, m_tag_information->data_tag, m_tag_information->data_tag_len);
                                obj_tag_len = m_tag_information->data_tag_len;
                            } else {
                                obj_tag[0] = 0xFF;
                                obj_tag[1] = 0x00;
                                obj_tag_len = 2;
                            }
                            obj_val = request + 1;
                            obj_len = length;
                            parsed = true;
                        }
                    }
                    if (!parsed || obj_val == NULL) {
                        NRF_LOG_ERROR("Seos: Update Data failed: Invalid object.");
                        break;
                    }
                    if (!seos_store_named_object(m_tag_information, obj_tag, obj_tag_len, obj_val, obj_len)) {
                        NRF_LOG_ERROR("Seos: Update Data failed: No room for object.");
                        break;
                    }
                } else {
                    uint8_t req_tags[SEOS_MAX_REQUESTED_TAGS][NFC_TAG_SEOS_DATA_TAG_MAX];
                    uint8_t req_tag_lens[SEOS_MAX_REQUESTED_TAGS];
                    uint8_t req_tag_count = 0;
                    if (!seos_parse_requested_tags(request, cryptogram_length, req_tags, req_tag_lens, &req_tag_count)) {
                        NRF_LOG_ERROR("Seos: Get Data failed: Invalid tag list.");
                        break;
                    }

                    uint8_t *reply = work_buffer_a;
                    uint16_t reply_idx = 0;
                    for (uint8_t i = 0; i < req_tag_count; i++) {
                        const uint8_t *obj_data = NULL;
                        uint8_t obj_len = 0;
                        if (!seos_find_object(m_tag_information, req_tags[i], req_tag_lens[i], &obj_data, &obj_len)) {
                            continue;
                        }
                        if ((uint16_t)(reply_idx + req_tag_lens[i] + 1 + obj_len) > WORK_BUFFER_SIZE) {
                            NRF_LOG_ERROR("Seos: Get Data failed: Unable to generate reply: too long.");
                            reply_idx = 0;
                            break;
                        }
                        memcpy(reply + reply_idx, req_tags[i], req_tag_lens[i]);
                        reply_idx += req_tag_lens[i];
                        reply[reply_idx++] = obj_len;
                        memcpy(reply + reply_idx, obj_data, obj_len);
                        reply_idx += obj_len;
                    }

                    if (reply_idx > 0) {
                        uint8_t reply_len = (uint8_t)round_to_next(reply_idx, bs);
                        if (reply_len > WORK_BUFFER_SIZE) {
                            NRF_LOG_ERROR("Seos: Get Data failed: Unable to generate reply: too long.");
                            break;
                        }

                        if (reply_idx != reply_len) {
                            memset(reply + reply_idx, 0, reply_len - reply_idx);
                            reply[reply_idx] = 0x80;
                        }

                        uint8_t *reply_cryptogram = work_buffer_b;
                        if (!generate_cryptogram(diver_encr_key, false, reply, reply_len, reply_cryptogram, m_tag_information->encr_alg)) {
                            NRF_LOG_ERROR("Seos: Get Data failed: Failed to create reply cryptogram.");
                            break;
                        }

                        if (2 + reply_len + 4 + 2 + recvd_cmac_length > NFC_14A_4_MAX_APDU) {
                            NRF_LOG_ERROR("Seos: Get Data failed: Response too large for buffer.");
                            break;
                        }

                        m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x85;
                        m_tcl_session_state.m_resp_buf[tlv_idx++] = reply_len;
                        memcpy(m_tcl_session_state.m_resp_buf + tlv_idx, reply_cryptogram, reply_len);
                        tlv_idx += reply_len;
                    }
                }

                // Whether we GET DATA or PUT DATA, add the response status code and CMAC
                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x99; // Tag: status code
                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x02; // Length
                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x90;
                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x00;

                // Unlike every other CMAC, this time we need to prepend
                //  the same counter from above, but increment it again
                for (int8_t i = bs - 1; i >= 0; i--) {
                    rndCounter[i]++;
                    if (rndCounter[i] != 0x00) break;
                }

                mac_input_idx = 0;

                memcpy(mac_input + mac_input_idx, rndCounter, bs);
                mac_input_idx += bs;
                if (mac_input_idx + tlv_idx + bs > WORK_BUFFER_SIZE) {
                    NRF_LOG_ERROR("Seos: Get Data failed: Reply CMAC input too large.");
                    break;
                }
                memcpy(mac_input + mac_input_idx, m_tcl_session_state.m_resp_buf, tlv_idx);
                mac_input_idx += tlv_idx;

                // Add padding (if needed) to mac_input
                if (mac_input_idx % bs) {
                    memset(mac_input + mac_input_idx, 0, bs - (mac_input_idx % bs));
                    mac_input[mac_input_idx] = 0x80;
                    mac_input_idx += bs - (mac_input_idx % bs);
                }

                uint8_t cmac_size = recvd_cmac_length;
                if (cmac_size > 16) {
                    NRF_LOG_ERROR("Seos: Get Data failed: CMAC size invalid.");
                    break;
                }

                if (!generate_cmac(diver_cmac_key, mac_input, mac_input_idx, cmac, m_tag_information->encr_alg)) {
                    NRF_LOG_ERROR("Seos: Get Data failed: Failed to create reply CMAC.");
                    break;
                }

                m_tcl_session_state.m_resp_buf[tlv_idx++] = 0x8E; // Tag: CMAC
                m_tcl_session_state.m_resp_buf[tlv_idx++] = cmac_size; // Length
                memcpy(m_tcl_session_state.m_resp_buf + tlv_idx, cmac, cmac_size);
                tlv_idx += cmac_size;

                m_tcl_session_state.m_resp_len = tlv_idx;

                // Set status code to Success
                apdu_status[0] = 0x90;
                apdu_status[1] = 0x00;
            } else {
                NRF_LOG_ERROR("Seos: Get Data failed: No cryptogram or CMAC found in request.");
                seos_sm_fail(apdu_status, SEOS_SW_SM_MISSING);
            }
        }
        break;
    }

    NRF_LOG_DEBUG("Seos: Responding with %d bytes, SW=%02X%02X.", m_tcl_session_state.m_resp_len, apdu_status[0], apdu_status[1]);
    NRF_LOG_HEXDUMP_DEBUG(m_tcl_session_state.m_resp_buf, m_tcl_session_state.m_resp_len);

    seos_commit_response(apdu_status);
}

/* ------------------------------------------------------------------ */
/*  Reset handler                                                       */
/* ------------------------------------------------------------------ */

void nfc_tag_seos_reset_handler(void) {
    nfc_tag_14a_4_reset_state(&m_tcl_session_state);
    seos_refresh_session();
}

/* ------------------------------------------------------------------ */
/*  Data load / save / factory callbacks                               */
/* ------------------------------------------------------------------ */

int nfc_tag_seos_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    int info_size = sizeof(nfc_tag_seos_information_t);
    if (buffer->length < info_size) {
        NRF_LOG_ERROR("SEOS loadcb: buffer too small (%d < %d)",
                      buffer->length, info_size);
        return info_size;
    }
    m_tag_information = (nfc_tag_seos_information_t *)buffer->buffer;
    if (!seos_gdf_record_valid(m_tag_information)) {
        seos_apply_factory_gdf(m_tag_information);
    }
    if (!seos_writekey_valid(m_tag_information)) {
        seos_apply_default_writekey(m_tag_information);
    }
    if (!seos_objects_valid(m_tag_information)) {
        seos_apply_empty_objects(m_tag_information);
    }
    memcpy(session_uid, m_tag_information->res_coll.uid, sizeof(session_uid));
    seos_refresh_session();

    nfc_tag_14a_handler_t handler = {
        .get_coll_res = nfc_tag_seos_get_coll_res,
        .cb_state     = nfc_tag_seos_state_handler,
        .cb_reset     = nfc_tag_seos_reset_handler,
    };
    nfc_tag_14a_set_handler(&handler);
    NRF_LOG_INFO("SEOS loadcb OK: SAK=%02x uid_sz=%d",
                 m_tag_information->res_coll.sak[0],
                 m_tag_information->res_coll.size);
    return info_size;
}

int nfc_tag_seos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    return sizeof(nfc_tag_seos_information_t);
}

bool nfc_tag_seos_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    if (tag_type != TAG_TYPE_SEOS) return false;

    /* Build factory defaults on stack and write directly to FDS
     * (same pattern as nfc_tag_mf1_data_factory). */
    nfc_tag_seos_information_t info;
    memset(&info, 0, sizeof(info));

    /* Placeholder 4-byte NXP-style UID */
    info.res_coll.size    = NFC_TAG_14A_UID_SINGLE_SIZE;
    info.res_coll.atqa[0] = 0x01;
    info.res_coll.atqa[1] = 0x00;
    info.res_coll.sak[0]  = 0x20;   /* ISO14443-4 */
    info.res_coll.uid[0]  = 0x08;
    info.res_coll.uid[1]  = 0x01;
    info.res_coll.uid[2]  = 0x02;
    info.res_coll.uid[3]  = 0x03;

    static const uint8_t default_ats[] = {
        0x05, 0x78, 0x77, 0x80, 0x02
    };
    info.res_coll.ats.length = sizeof(default_ats);
    memcpy(info.res_coll.ats.data, default_ats, sizeof(default_ats));

    // Load default values
    const uint8_t DEFAULT_DATA[] = {0x05, 0x00};
    const uint8_t DEFAULT_OID[] = {0x03, 0x01, 0x07, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t DEFAULT_TAG[] = {0xFF, 0x00};
    const uint8_t DEFAULT_DIVERSIFIER[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    info.data_len = sizeof(DEFAULT_DATA);
    memcpy(info.data, DEFAULT_DATA, info.data_len);

    info.oid_len = sizeof(DEFAULT_OID);
    memcpy(info.oid, DEFAULT_OID, info.oid_len);

    info.data_tag_len = sizeof(DEFAULT_TAG);
    memcpy(info.data_tag, DEFAULT_TAG, info.data_tag_len);

    info.diversifier_len = sizeof(DEFAULT_DIVERSIFIER);
    memcpy(info.diversifier, DEFAULT_DIVERSIFIER, info.diversifier_len);

    memset(info.authkey, 0, 16);
    memset(info.privenc, 0, 16);
    memset(info.privmac, 0, 16);

    info.encr_alg = SEOS_ENCRYPTION_AES;
    info.hash_alg = SEOS_HASHING_SHA256;
    seos_apply_factory_gdf(&info);
    seos_apply_default_writekey(&info);
    seos_apply_empty_objects(&info);

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(info), &info);
    NRF_LOG_INFO("SEOS factory slot %d: %s", slot, ret ? "OK" : "FAIL");
    return ret;
}
