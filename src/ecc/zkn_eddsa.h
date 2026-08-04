#ifndef _ZKN_EDDSA_H
#define _ZKN_EDDSA_H

#include "zkn_bn.h"
#include "zkn_hash_compat.h"

int zkn_prv_hash(const uint8_t *prv, uint8_t *out, size_t len);

int zkn_prv2pub(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub);

/* EDDSA POSEIDON*/
#define _EDDSA_POSEIDON_NINPUTS 5

int EddsaPoseidon_Sign_final(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub, uint8_t *msg, size_t len, uint8_t *out);

#ifdef ZKNOX_DEBUG
/* CX-sign wipe bisection instrumentation. Host sets `zkn_debug_stop_at`
 * to K ∈ [1..N]; sign_final early-returns ZKN_OK at CP K without executing
 * subsequent code. K == 0 (default) runs the full sign path unchanged.
 * Prod builds have this symbol UNDEFINED — no runtime cost, no way to
 * activate. See docs/ or the sign-checkpoint JS test for CP numbering. */
extern uint8_t zkn_debug_stop_at;
#endif

#endif