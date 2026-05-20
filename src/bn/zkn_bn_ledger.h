#ifndef _ZKN_BN_H
#define _ZKN_BN_H

int zkn_montgomery_export(cx_bn_mont_ctx_t *mont, cx_bn_t in, uint8_t *out, size_t *len);

#endif