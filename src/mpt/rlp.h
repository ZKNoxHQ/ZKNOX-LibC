/**
 * rlp.h  —  Minimal RLP decoder (Ethereum Yellow Paper Appendix B)
 *
 * Supporte uniquement le décodage (pas l'encodage).
 * Limites volontaires pour le Nano : pas d'allocation dynamique.
 */
#pragma once
#include <stdint.h>
#include <string.h>

/* Type d'un item RLP */
typedef enum {
    RLP_STR  = 0,  /* byte string */
    RLP_LIST = 1,  /* liste d'items */
} RlpType;

/* Item RLP — pointe dans le buffer source (pas de copie) */
typedef struct {
    RlpType        type;
    const uint8_t *data;   /* contenu (string) ou début des items (list) */
    uint32_t       len;    /* longueur en bytes */
} RlpItem;

/* Résultat d'un décodage */
typedef enum {
    RLP_OK = 0,
    RLP_ERR_TRUNC,   /* buffer trop court */
    RLP_ERR_OVERFLOW,/* longueur encodée dépasse uint32 */
    RLP_ERR_TOOBIG,  /* item dépasse le buffer */
    RLP_ERR_NONCANONICAL, /* encodage non minimal */
} RlpErr;

/**
 * rlp_decode — décode le premier item RLP dans buf[0..buf_len)
 *
 * @param buf     buffer source
 * @param buf_len longueur du buffer
 * @param out     item décodé (pointe dans buf)
 * @param consumed bytes consommés (header + data)
 */
static RlpErr rlp_decode(const uint8_t *buf, uint32_t buf_len,
                          RlpItem *out, uint32_t *consumed)
{
    /* SECURITY: the length checks used to be written `1 + llen + slen >
     * buf_len` in uint32_t arithmetic. A long-form header carrying a length of
     * 0xFFFFFFFF wraps that sum to `llen` and passes, returning an item whose
     * `len` points ~4 GiB past the buffer. The long forms also accepted up to
     * 8 length bytes, silently truncated into a uint32_t. All comparisons are
     * now done by subtraction against the remaining space, the length-of-length
     * is capped at 4 bytes, and non-minimal encodings are rejected. */
    if (buf_len == 0) return RLP_ERR_TRUNC;

    uint8_t prefix = buf[0];
    const uint32_t rem = buf_len - 1;          /* bytes after the prefix */

    /* ── Single byte ── */
    if (prefix <= 0x7f) {
        out->type = RLP_STR;
        out->data = buf;
        out->len  = 1;
        *consumed = 1;
        return RLP_OK;
    }

    /* ── Short string (0-55 bytes) ── */
    if (prefix <= 0xb7) {
        uint32_t slen = prefix - 0x80;
        if (slen > rem) return RLP_ERR_TRUNC;
        if (slen == 1 && buf[1] <= 0x7f) return RLP_ERR_NONCANONICAL;
        out->type = RLP_STR;
        out->data = buf + 1;
        out->len  = slen;
        *consumed = 1 + slen;
        return RLP_OK;
    }

    /* ── Long string / long list share the length decoding ── */
    if (prefix <= 0xbf || prefix > 0xf7) {
        uint8_t llen = (prefix <= 0xbf) ? (uint8_t)(prefix - 0xb7) : (uint8_t)(prefix - 0xf7);
        if (llen > 4) return RLP_ERR_OVERFLOW;
        if (llen > rem) return RLP_ERR_TRUNC;
        if (buf[1] == 0) return RLP_ERR_NONCANONICAL;          /* leading zero */
        uint32_t plen = 0;
        for (uint8_t i = 0; i < llen; i++) plen = (plen << 8) | buf[1 + i];
        if (plen < 56) return RLP_ERR_NONCANONICAL;            /* should be short form */
        if (plen > rem - llen) return RLP_ERR_TRUNC;
        out->type = (prefix <= 0xbf) ? RLP_STR : RLP_LIST;
        out->data = buf + 1 + llen;
        out->len  = plen;
        *consumed = 1 + llen + plen;
        return RLP_OK;
    }

    /* ── Short list (0-55 bytes payload) ── */
    {
        uint32_t plen = prefix - 0xc0;
        if (plen > rem) return RLP_ERR_TRUNC;
        out->type = RLP_LIST;
        out->data = buf + 1;
        out->len  = plen;
        *consumed = 1 + plen;
        return RLP_OK;
    }
}

/**
 * rlp_list_item — itérateur : extrait le Nième item d'une liste RLP
 *
 * @param list  item de type RLP_LIST
 * @param idx   index 0-based
 * @param out   item résultat
 */
static RlpErr rlp_list_item(const RlpItem *list, uint32_t idx, RlpItem *out)
{
    if (list->type != RLP_LIST) return RLP_ERR_TRUNC;
    const uint8_t *p   = list->data;
    uint32_t       rem = list->len;
    uint32_t       i   = 0;

    while (rem > 0) {
        uint32_t consumed;
        RlpErr e = rlp_decode(p, rem, out, &consumed);
        if (e != RLP_OK) return e;
        if (i == idx) return RLP_OK;
        p   += consumed;
        rem -= consumed;
        i++;
    }
    return RLP_ERR_TRUNC;  /* idx hors limites */
}

/**
 * rlp_list_count — compte les items d'une liste RLP
 */
static uint32_t rlp_list_count(const RlpItem *list)
{
    if (list->type != RLP_LIST) return 0;
    const uint8_t *p   = list->data;
    uint32_t       rem = list->len;
    uint32_t       n   = 0;
    while (rem > 0) {
        RlpItem tmp; uint32_t c;
        if (rlp_decode(p, rem, &tmp, &c) != RLP_OK) break;
        p += c; rem -= c; n++;
    }
    return n;
}
