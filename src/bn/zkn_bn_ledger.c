/*
 * zkn_bn_ledger.c — Ledger-specific helper functions
 *
 * These helpers (zkn_montgomery_init / zkn_montgomery_export) use the
 * Ledger SDK cx_bn_* / cx_mont_* primitives directly. They have no
 * software-backend equivalent, so the entire file is conditionally
 * compiled only when ZKN_BN_BACKEND_LEDGER is defined.
 *
 * For consumers that need similar helpers in software mode, equivalent
 * functionality is available via the standard zkn_bn_* / zkn_mont_*
 * API (see zkn_bn_sw.h).
 */

#ifdef ZKN_BN_BACKEND_LEDGER

#include <stdint.h>  // uint*_t
#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include "os.h"
#include "cx.h"
#include "zkn_errors.h"
/* import from  MSB hexa to Montgomery*/
/* out is already allocated*/
int zkn_montgomery_init(cx_bn_mont_ctx_t *mont, uint8_t *in, size_t len, cx_bn_t out)
{
    ZKN_ERROR_INIT();
    cx_bn_t tmp;
    ZKN_CHECK(cx_bn_alloc(&tmp, len));
    ZKN_CHECK(cx_bn_init(tmp, in, len));
    ZKN_CHECK(cx_mont_to_montgomery(tmp, out, mont));
    ZKN_CHECK(cx_bn_destroy(&tmp));
    ZKN_ERROR_CLOSE();
}
/* export from Montgomery to MSB hexa*/
int zkn_montgomery_export(cx_bn_mont_ctx_t *mont, cx_bn_t in, uint8_t *out, size_t len)
{
    ZKN_ERROR_INIT();
    cx_bn_t tmp;
    ZKN_CHECK(cx_bn_alloc(&tmp, len));
    ZKN_CHECK(cx_mont_from_montgomery(tmp, in, mont));
    ZKN_CHECK(cx_bn_export(tmp, out, len));
    ZKN_CHECK(cx_bn_destroy(&tmp));
    ZKN_ERROR_CLOSE();
}

#endif /* ZKN_BN_BACKEND_LEDGER */
