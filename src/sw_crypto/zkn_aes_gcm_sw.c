/* Software crypto — HOST ONLY. Uses calloc/free, unavailable on BOLOS (no heap).
 * The Ledger app build sweeps every .c under the submodule, so this guard makes
 * the file an empty translation unit on device. */
#ifdef ZKN_HOST_BUILD
/* aes_gcm_sw.c — software AES-256-GCM (no AAD, 16-byte IV), matching Node's
 * createCipheriv('aes-256-gcm', key32, iv16) and BOLOS cx_aes_gcm_* / the
 * RAILGUN engine note-encryption. Self-contained; host-testable. */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ---------------- AES-256 core ---------------- */
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static uint8_t xtime(uint8_t x){ return (uint8_t)((x<<1) ^ ((x>>7)*0x1b)); }
#define NR 14
static void key_expand(const uint8_t key[32], uint8_t rk[(NR+1)*16]){
  memcpy(rk, key, 32);
  uint8_t rcon=1;
  for(int i=8;i<(NR+1)*4;i++){
    uint8_t t[4]; memcpy(t, rk+(i-1)*4, 4);
    if(i%8==0){ uint8_t tmp=t[0]; t[0]=SBOX[t[1]]^rcon; t[1]=SBOX[t[2]]; t[2]=SBOX[t[3]]; t[3]=SBOX[tmp]; rcon=xtime(rcon); }
    else if(i%8==4){ for(int j=0;j<4;j++) t[j]=SBOX[t[j]]; }
    for(int j=0;j<4;j++) rk[i*4+j] = rk[(i-8)*4+j] ^ t[j];
  }
}
static void aes_encrypt_block(const uint8_t rk[(NR+1)*16], const uint8_t in[16], uint8_t out[16]){
  uint8_t s[16]; memcpy(s,in,16);
  for(int i=0;i<16;i++) s[i]^=rk[i];
  for(int r=1;r<=NR;r++){
    uint8_t t[16];
    for(int i=0;i<16;i++) t[i]=SBOX[s[i]];
    uint8_t sh[16]={ t[0],t[5],t[10],t[15], t[4],t[9],t[14],t[3], t[8],t[13],t[2],t[7], t[12],t[1],t[6],t[11] };
    if(r<NR){
      for(int c=0;c<4;c++){ uint8_t *col=sh+c*4; uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
        col[0]=(uint8_t)(xtime(a0)^(xtime(a1)^a1)^a2^a3);
        col[1]=(uint8_t)(a0^xtime(a1)^(xtime(a2)^a2)^a3);
        col[2]=(uint8_t)(a0^a1^xtime(a2)^(xtime(a3)^a3));
        col[3]=(uint8_t)((xtime(a0)^a0)^a1^a2^xtime(a3)); }
    }
    for(int i=0;i<16;i++) s[i]=sh[i]^rk[r*16+i];
  }
  memcpy(out,s,16);
}
/* ---------------- GHASH (GF(2^128)) ---------------- */
static void ghash_mul(uint8_t X[16], const uint8_t H[16]){
  uint8_t Z[16]={0}, V[16]; memcpy(V,H,16);
  for(int i=0;i<128;i++){
    if((X[i/8]>>(7-(i%8)))&1) for(int j=0;j<16;j++) Z[j]^=V[j];
    int lsb=V[15]&1;
    for(int j=15;j>0;j--) V[j]=(uint8_t)((V[j]>>1)|((V[j-1]&1)<<7));
    V[0]>>=1;
    if(lsb) V[0]^=0xe1;
  }
  memcpy(X,Z,16);
}
static void ghash(const uint8_t H[16], const uint8_t *data, size_t len, uint8_t Y[16]){
  size_t n=len/16;
  for(size_t i=0;i<n;i++){ for(int j=0;j<16;j++) Y[j]^=data[i*16+j]; ghash_mul(Y,H); }
  if(len%16){ uint8_t last[16]={0}; memcpy(last,data+n*16,len%16); for(int j=0;j<16;j++) Y[j]^=last[j]; ghash_mul(Y,H); }
}
static void inc32(uint8_t ctr[16]){ for(int i=15;i>=12;i--){ if(++ctr[i]) break; } }

/* AES-256-GCM, no AAD, arbitrary IV length. ct has same length as pt; tag[16]. */
/* core: AES-256-GCM with optional AAD, arbitrary IV length. */
static void gcm_core(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t inlen, uint8_t *out,
                     uint8_t tag[16], int encrypt)
{
  uint8_t rk[(NR+1)*16]; key_expand(key,rk);
  uint8_t H[16]={0}; aes_encrypt_block(rk,H,H);
  /* J0 */
  uint8_t J0[16]={0};
  if(ivlen==12){ memcpy(J0,iv,12); J0[15]=1; }
  else{
    uint8_t Y[16]={0}; ghash(H,iv,ivlen,Y);
    uint8_t lenblk[16]={0}; uint64_t bits=(uint64_t)ivlen*8;
    for(int i=0;i<8;i++) lenblk[15-i]=(uint8_t)(bits>>(8*i));
    for(int j=0;j<16;j++) Y[j]^=lenblk[j];
    ghash_mul(Y,H); memcpy(J0,Y,16);
  }
  /* S = GHASH(AAD || C || lens) — C is the ciphertext in both directions */
  uint8_t S[16]={0};
  if(aadlen) ghash(H,aad,aadlen,S);
  const uint8_t *ctext = encrypt ? out : in;
  /* GCTR */
  uint8_t ctr[16]; memcpy(ctr,J0,16);
  for(size_t off=0;off<inlen;off+=16){
    inc32(ctr); uint8_t ks[16]; aes_encrypt_block(rk,ctr,ks);
    size_t n=inlen-off<16?inlen-off:16;
    for(size_t j=0;j<n;j++) out[off+j]=in[off+j]^ks[j];
  }
  ghash(H,ctext,inlen,S);
  uint8_t lenblk[16]={0};
  uint64_t abits=(uint64_t)aadlen*8, cbits=(uint64_t)inlen*8;
  for(int i=0;i<8;i++) lenblk[7-i]=(uint8_t)(abits>>(8*i));
  for(int i=0;i<8;i++) lenblk[15-i]=(uint8_t)(cbits>>(8*i));
  for(int j=0;j<16;j++) S[j]^=lenblk[j]; ghash_mul(S,H);
  uint8_t EJ0[16]; aes_encrypt_block(rk,J0,EJ0);
  for(int j=0;j<16;j++) tag[j]=S[j]^EJ0[j];
}

void zkn_sw_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                               const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]){
  gcm_core(key,iv,ivlen,NULL,0,pt,ptlen,ct,tag,1);
}

void zkn_sw_aes256_gcm_encrypt_aad(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                                   const uint8_t *aad, size_t aadlen,
                                   const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]){
  gcm_core(key,iv,ivlen,aad,aadlen,pt,ptlen,ct,tag,1);
}

/* returns 0 on success (tag valid), -1 on authentication failure. */
int zkn_sw_aes256_gcm_decrypt_aad(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                                  const uint8_t *aad, size_t aadlen,
                                  const uint8_t *ct, size_t ctlen, const uint8_t tag[16],
                                  uint8_t *pt){
  uint8_t t[16];
  gcm_core(key,iv,ivlen,aad,aadlen,ct,ctlen,pt,t,0);
  uint8_t diff=0; for(int i=0;i<16;i++) diff|=(uint8_t)(t[i]^tag[i]);   /* constant-time */
  if(diff){ memset(pt,0,ctlen); return -1; }
  return 0;
}

#endif /* ZKN_HOST_BUILD */
