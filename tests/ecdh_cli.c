/* ecdh_cli.c — exercise the unified comms-crypto API (backend-agnostic):
 *   kdf     <scalar_be32> <VK_compressed>        -> aes key (32B)
 *   smul    <scalar_be32> <point_compressed>     -> compressed point
 *   gcm     <key32> <iv16> <plaintext_hex>       -> ciphertext||tag
 * Uses only zkn_ed25519_ecdh.h / zkn_aes_gcm.h — identical on SW and Ledger. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zkn_ed25519_ecdh.h"
#include "zkn_aes_gcm.h"
static int unhex(const char*s,uint8_t*o,size_t n){ if(strlen(s)!=2*n) return -1; for(size_t i=0;i<n;i++) if(sscanf(s+2*i,"%2hhx",&o[i])!=1) return -1; return 0; }
static void ph(const uint8_t*b,size_t n){ for(size_t i=0;i<n;i++) printf("%02x",b[i]); }
int main(int argc,char**argv){
  if(argc<2) return 2;
  if(!strcmp(argv[1],"kdf")&&argc==4){ uint8_t s[32],vk[32],k[32];
    if(unhex(argv[2],s,32)||unhex(argv[3],vk,32)) return 2;
    if(zkn_ed25519_ecdh_kdf(s,vk,k)) return 1; ph(k,32); printf("\n"); return 0; }
  if(!strcmp(argv[1],"smul")&&argc==4){ uint8_t s[32],p[32],o[32];
    if(unhex(argv[2],s,32)||unhex(argv[3],p,32)) return 2;
    if(zkn_ed25519_scalarmul_compressed(s,p,o)) return 1; ph(o,32); printf("\n"); return 0; }
  if(!strcmp(argv[1],"gcm")&&argc==5){ uint8_t k[32],iv[16],tag[16];
    if(unhex(argv[2],k,32)||unhex(argv[3],iv,16)) return 2;
    size_t n=strlen(argv[4])/2; uint8_t*pt=malloc(n?n:1),*ct=malloc(n?n:1);
    if(n&&unhex(argv[4],pt,n)) return 2;
    if(zkn_aes256_gcm_encrypt(k,iv,pt,n,ct,tag)) return 1;
    ph(ct,n); ph(tag,16); printf("\n"); return 0; }
  return 2;
}
