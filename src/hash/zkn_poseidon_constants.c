#include <stdint.h>
#include <stdlib.h>

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"

#include "zkn_errors.h"
#include "zkn_common.h"
#include "zkn_poseidon_constants.h"

// from https://eprint.iacr.org/2019/458.pdf
//  Polynomes Grain v1
//  LFSR: x^80 + x^62 + x^51 + x^38 + x^23 + x^13 + 1
#define GRAIN_TAPS ((1ULL << 0) | (1ULL << 13) | (1ULL << 23) | (1ULL << 38) | (1ULL << 51) | (1ULL << 62))
#define GRAIN_MASK_LOW_64 0xffffffffffffffff
#define GRAIN_MASK_HI_16 0xffff

/*=== INIT_SEQUENCE Details ===
Length: 80 bits
Binary: 01000000001111111000000000011000000010000000111100111111111111111111111111111111
Hex:    0x403F8018080F3FFFFFFF*/

#define _INIT_SEQ_LOW 0xFFFCF0101801FC02
#define _INIT_SEQ_HI 0xFFFF

uint64_t grain_lfsr_advance(uint64_t state[2])
{
  uint64_t feedback = state[0] & GRAIN_TAPS;

  feedback = (feedback >> 32) ^ (feedback);
  feedback = (feedback >> 16) ^ (feedback);
  feedback = (feedback >> 8) ^ (feedback);
  feedback = (feedback >> 4) ^ (feedback);
  feedback = (feedback >> 2) ^ (feedback);
  feedback = ((feedback >> 1) ^ (feedback)) & 1;

  state[0] = (state[0] >> 1) ^ ((state[1] & 1) << 63); // shift low register, plus low bit of high register
  state[1] = (state[1] >> 1) ^ ((feedback) << 15);     // shift hi register plus feedback

  return feedback & 1;
}

// generate the next 64 bits
uint64_t next64_graingen(uint64_t state[2], size_t len)
{
  uint64_t out = 0;
  size_t cpt = 0;
  uint64_t temp;
  // printf("\n");
  while (cpt < len)
  {
    temp = grain_lfsr_advance(state);
    temp = (temp << 1) + grain_lfsr_advance(state);

    if (temp & 0x2)
    {
      // printf(" %x", temp&1);
      out = (out << 1) + (temp & 1);
      cpt++;
    }
  }
  return out;
}

void init_generator(uint64_t state[2])
{
  state[0] = _INIT_SEQ_LOW;
  state[1] = _INIT_SEQ_HI;

  for (int i = 0; i < 160; i++)
  {
    grain_lfsr_advance(state);
  }
}

void gen_integer(uint64_t state[2], uint64_t out[4])
{
  int flag = 0;

  while (flag == 0)
  {

    out[0] = next64_graingen(state, 62);
    out[1] = next64_graingen(state, 64);
    out[2] = next64_graingen(state, 64);
    out[3] = next64_graingen(state, 64);

    if (out[0] > 0x305a4b4e4f582121)
    { // magic number
      flag = 0;
    }
    else
      flag = 1;
  }

  // Swap because of ARM endianness
  out[0] = rev64(out[0]);
  out[1] = rev64(out[1]);
  out[2] = rev64(out[2]);
  out[3] = rev64(out[3]);
}

// those constants are stored in raw format, todo: convert to montgomery representation
static int Poseidon_Mix(poseidon_ctx_t *ctx)
{
  ZKN_ERROR_INIT();

  for (size_t i = 0; i < ctx->nb_state_cells; i++)
  {
    ZKN_CHECK(zkn_bn_set_u32(ctx->tmp[i], 0));
    for (size_t j = 0; j < ctx->nb_state_cells; j++)
    {
      ZKN_CHECK(zkn_mont_mul(ctx->temp, ctx->state[j], ctx->MixColumn[(i * ctx->nb_state_cells) + j], ctx->mont));
      ZKN_CHECK(zkn_bn_mod_add(ctx->tmp[i], ctx->tmp[i], ctx->temp, ctx->mont->n));
    }
  }

  for (size_t i = 0; i < ctx->nb_state_cells; i++)
  {
    ZKN_CHECK(zkn_bn_copy(ctx->state[i], ctx->tmp[i])); // todo try the pointer swap
  }

  ZKN_ERROR_CLOSE();
}

void Poseidon_getNext_RC(poseidon_ctx_t *ctx, uint64_t out[4])
{
  gen_integer(ctx->grain_state, out);
}

// allocate Poseidon structure
int Poseidon_alloc_init(poseidon_ctx_t *ctx, uint32_t pow, size_t nb_inputs, zkn_bn_mont_ctx_t *initialized_montctx)
{
  ZKN_ERROR_INIT();

#ifdef _DYN_GEN
  init_generator(ctx->grain_state);
#endif

  uint8_t MixColumn[_MAX_POSEIDON_nCELLS * _MAX_POSEIDON_nCELLS * 32] = Poseidon_MixColumnMatrix;

  ctx->current_index = 0;
  ctx->pow[0] = (uint8_t)pow;          // todo: automatize the pow used in sigma, 3 (if p!=1 mod ) or 5
  ctx->nb_inputs = nb_inputs;          // number of inputs, ex5 for poseidon5 (target for eddsa poseidon of circom)
  ctx->nb_state_cells = nb_inputs + 1; // inputs of poseidon
  ctx->mont = initialized_montctx;     // pointer to an initialized montgomery context

  ZKN_CHECK(zkn_bn_nbytes(initialized_montctx->n, &ctx->fieldsize8)); // size is the size of the modulus

  size_t size8 = ctx->fieldsize8;

  // Allocate State and MixColumnMatrix

  ZKN_CHECK(zkn_bn_alloc(&(ctx->temp), size8)); // tmp
  for (size_t i = 0; i < ctx->nb_state_cells; i++)
  {

    ZKN_CHECK(zkn_bn_alloc(&(ctx->state[i]), size8)); // state
    ZKN_CHECK(zkn_bn_alloc(&(ctx->tmp[i]), size8));   // tmp

    for (size_t j = 0; j < ctx->nb_state_cells; j++)
    { // mixcolumn
      ZKN_CHECK(zkn_bn_alloc_init(&(ctx->MixColumn[i * ctx->nb_state_cells + j]), size8, MixColumn + (size8 * (i * ctx->nb_state_cells + j)), size8));
      ZKN_CHECK(zkn_mont_to_montgomery((ctx->MixColumn[i * ctx->nb_state_cells + j]), (ctx->MixColumn[i * ctx->nb_state_cells + j]), ctx->mont));
    }
  }

  ctx->status = _ZKN_INITIALIZED;
  ZKN_ERROR_CLOSE();
}

// desallocate poseidon structure
int Poseidon_destroy(poseidon_ctx_t *ctx)
{
  ZKN_ERROR_INIT();

  if (ctx->status != _ZKN_INITIALIZED)
  {
    return ZKN_NOT_INITIALIZED;
  }
  // Desallocate MixColumnMatrix
  for (size_t i = 0; i < ctx->nb_state_cells; i++)
  {
    ZKN_CHECK(zkn_bn_destroy(&(ctx->state[i]))); // state
    ZKN_CHECK(zkn_bn_destroy(&(ctx->tmp[i])));   // tmp
    for (size_t j = 0; j < ctx->nb_state_cells; j++)
    {
      ZKN_CHECK(zkn_bn_destroy(&(ctx->MixColumn[i * ctx->nb_state_cells + j])));
    }
  }

  ZKN_CHECK(zkn_bn_destroy(&(ctx->temp))); // tmp

  ZKN_ERROR_CLOSE();
}

static int Poseidon_AddRoundC(poseidon_ctx_t *ctx)
{

  ZKN_ERROR_INIT();
  // ZKN_CHECK(zkn_bn_alloc(&tmp,fieldS8));
  uint64_t rc[4];
  zkn_bn_t *rc_bn = ctx->tmp; // avoid allocation
  size_t size8 = ctx->fieldsize8;

  // ZKN_CHECK(zkn_bn_alloc(&rc_bn, size8));

  for (size_t i = 0; i < ctx->nb_state_cells; i++)
  {
    Poseidon_getNext_RC(ctx, rc);
    ZKN_CHECK(zkn_bn_init(*rc_bn, (uint8_t *)rc, size8));         // todo: montgomerize the constants
    ZKN_CHECK(zkn_mont_to_montgomery(*rc_bn, *rc_bn, ctx->mont)); // todo: montgomerize the constants
    ZKN_CHECK(zkn_bn_mod_add(ctx->state[i], *rc_bn, ctx->state[i], ctx->mont->n));
  }

  // ZKN_CHECK(zkn_bn_destroy(&rc_bn));

  ZKN_ERROR_CLOSE();
}

// the inside power function (3 or 5)
static int Poseidon_Sigma(poseidon_ctx_t *ctx)
{
  ZKN_ERROR_INIT();

  // for(size_t i=0;i<ctx->nb_state_cells;i++){
  //         ZKN_CHECK(zkn_mont_pow(ctx->state[i], ctx->state[i], ctx->pow, (uint32_t) 1, ctx->mont));
  // }

  // specific case: pow=5
  for (size_t i = 0; i < ctx->nb_state_cells; i++)
  {
    // ZKN_CHECK(zkn_mont_pow(ctx->state[i], ctx->state[i], ctx->pow, (uint32_t) 1, ctx->mont));
    ZKN_CHECK(zkn_mont_mul(ctx->tmp[0], ctx->state[i], ctx->state[i], ctx->mont)); // X^2
    ZKN_CHECK(zkn_mont_mul(ctx->tmp[1], ctx->tmp[0], ctx->tmp[0], ctx->mont));     // X^4
    ZKN_CHECK(zkn_mont_mul(ctx->state[i], ctx->state[i], ctx->tmp[1], ctx->mont)); // X^5
  }

  ZKN_ERROR_CLOSE();
}

// full poseidon hash, output is montgomerized
int Poseidon(poseidon_ctx_t *ctx, uint32_t initState, zkn_bn_t *out, size_t sizeout)
{
  ZKN_ERROR_INIT();

  if (ctx->status != _ZKN_INITIALIZED)
  {
    return ZKN_NOT_INITIALIZED;
  }

  ZKN_CHECK(zkn_bn_set_u32(ctx->state[0], initState));

  for (size_t r = 0; r < nRoundsF + nRoundsP; r++)
  {
    // for (size_t r = 0; r < 1; r++) {
    ZKN_CHECK(Poseidon_AddRoundC(ctx));

    if (r < nRoundsF / 2 || r >= nRoundsF / 2 + nRoundsP)
    { // fullrounds
      ZKN_CHECK(Poseidon_Sigma(ctx));
    }
    else
    {
      ZKN_CHECK(zkn_mont_pow(ctx->state[0], ctx->state[0], ctx->pow, (uint32_t)1, ctx->mont));
    }

    ZKN_CHECK(Poseidon_Mix(ctx)); // matricial multiplication: M.state
  }

  for (size_t i = 0; i < sizeout; i++)
  {
    ZKN_CHECK(zkn_bn_copy(out[i], ctx->state[i]));
  }

  ZKN_ERROR_CLOSE();
}
