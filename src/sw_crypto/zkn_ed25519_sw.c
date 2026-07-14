/* ed25519_sw.c — software edwards25519 scalar mult + RFC8032 (de)compression,
 * for the RAILGUN-engine ECDH-KDF: AES_KEY = SHA-256(compressed [scalar]·P).
 * Field/point ops ported from TweetNaCl (public domain, D. J. Bernstein et al). */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef int64_t gf[16];
typedef uint8_t u8; typedef int64_t i64;
static const gf gf0={0}, gf1={1},
 D={0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070,0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203},
 D2={0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406},
 X={0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169},
 Y={0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666},
 I={0xa0b0,0x4a0e,0x1b27,0xc4ee,0xe478,0xad2f,0x1806,0x2f43,0xd7a7,0x3dfb,0x0099,0x2b4d,0xdf0b,0x4fc1,0x2480,0x2b83};
static void set25519(gf r,const gf a){ for(int i=0;i<16;i++) r[i]=a[i]; }
static void car25519(gf o){ for(int i=0;i<16;i++){ o[i]+=(1LL<<16); i64 c=o[i]>>16; o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15); o[i]-=c<<16; } }
static void sel25519(gf p,gf q,int b){ i64 c=~(b-1); for(int i=0;i<16;i++){ i64 t=c&(p[i]^q[i]); p[i]^=t; q[i]^=t; } }
static void pack25519(u8*o,const gf n){ gf m,t; set25519(t,n); car25519(t); car25519(t); car25519(t);
 for(int j=0;j<2;j++){ m[0]=t[0]-0xffed; for(int i=1;i<15;i++){ m[i]=t[i]-0xffff-((m[i-1]>>16)&1); m[i-1]&=0xffff; } m[15]=t[15]-0x7fff-((m[14]>>16)&1); int b=(m[15]>>16)&1; m[14]&=0xffff; sel25519(t,m,1-b); }
 for(int i=0;i<16;i++){ o[2*i]=t[i]&0xff; o[2*i+1]=t[i]>>8; } }
static int neq25519(const gf a,const gf b){ u8 c[32],d[32]; pack25519(c,a); pack25519(d,b); return memcmp(c,d,32); }
static u8 par25519(const gf a){ u8 d[32]; pack25519(d,a); return d[0]&1; }
static void unpack25519(gf o,const u8*n){ for(int i=0;i<16;i++) o[i]=n[2*i]+((i64)n[2*i+1]<<8); o[15]&=0x7fff; }
static void A(gf o,const gf a,const gf b){ for(int i=0;i<16;i++) o[i]=a[i]+b[i]; }
static void Z(gf o,const gf a,const gf b){ for(int i=0;i<16;i++) o[i]=a[i]-b[i]; }
static void M(gf o,const gf a,const gf b){ i64 t[31]; for(int i=0;i<31;i++) t[i]=0;
 for(int i=0;i<16;i++) for(int j=0;j<16;j++) t[i+j]+=a[i]*b[j];
 for(int i=0;i<15;i++) t[i]+=38*t[i+16]; for(int i=0;i<16;i++) o[i]=t[i]; car25519(o); car25519(o); }
static void S(gf o,const gf a){ M(o,a,a); }
static void inv25519(gf o,const gf i){ gf c; set25519(c,i); for(int a=253;a>=0;a--){ S(c,c); if(a!=2&&a!=4) M(c,c,i); } set25519(o,c); }
static void pow2523(gf o,const gf i){ gf c; set25519(c,i); for(int a=250;a>=0;a--){ S(c,c); if(a!=1) M(c,c,i); } set25519(o,c); }
/* point in extended coords P=[X,Y,Z,T] */
static void add(gf p[4],gf q[4]){ gf a,b,c,d,t,e,f,g,h;
 Z(a,p[1],p[0]); Z(t,q[1],q[0]); M(a,a,t); A(b,p[0],p[1]); A(t,q[0],q[1]); M(b,b,t);
 M(c,p[3],q[3]); M(c,c,D2); M(d,p[2],q[2]); A(d,d,d);
 Z(e,b,a); Z(f,d,c); A(g,d,c); A(h,b,a);
 M(p[0],e,f); M(p[1],h,g); M(p[2],g,f); M(p[3],e,h); }
static void cswap(gf p[4],gf q[4],u8 b){ for(int i=0;i<4;i++) sel25519(p[i],q[i],b); }
static void pack(u8*r,gf p[4]){ gf tx,ty,zi; inv25519(zi,p[2]); M(tx,p[0],zi); M(ty,p[1],zi); pack25519(r,ty); r[31]^=par25519(tx)<<7; }
static void scalarmult(gf p[4],gf q[4],const u8*s){ set25519(p[0],gf0); set25519(p[1],gf1); set25519(p[2],gf1); set25519(p[3],gf0);
 for(int i=255;i>=0;i--){ u8 b=(s[i/8]>>(i&7))&1; cswap(p,q,b); add(q,p); add(p,p); cswap(p,q,b); } }
/* unpack a compressed point to +P (edwards). returns 0 on success */
static int unpack(gf r[4],const u8*p){ gf num,den,chk,t,den2,den4,den6; set25519(r[2],gf1); unpack25519(r[1],p);
 S(num,r[1]); M(den,num,D); Z(num,num,r[2]); A(den,r[2],den);
 S(den2,den); S(den4,den2); M(den6,den4,den2); M(t,den6,num); M(t,t,den);
 pow2523(t,t); M(t,t,num); M(t,t,den); M(t,t,den); M(r[0],t,den);
 S(chk,r[0]); M(chk,chk,den); if(neq25519(chk,num)) M(r[0],r[0],I);
 S(chk,r[0]); M(chk,chk,den); if(neq25519(chk,num)) return -1;
 if(par25519(r[0])!=(p[31]>>7)) Z(r[0],gf0,r[0]);
 M(r[3],r[0],r[1]); return 0; }

/* SHA-256 (from sha256_sw.c, inlined via extern) */
void zkn_sw_sha256(const uint8_t*msg,size_t len,uint8_t out[32]);

/* ecdh-kdf: out = SHA-256( compressed( [scalar_le]·unpack(VK) ) ). scalar is 32B little-endian. */
int zkn_sw_ed25519_ecdh_kdf(const u8 scalar_le[32], const u8 VK[32], u8 out[32]){
 gf P[4],Q[4]; if(unpack(Q,VK)) return -1; scalarmult(P,Q,scalar_le); u8 shared[32]; pack(shared,P); zkn_sw_sha256(shared,32,out); return 0; }
/* also expose raw compressed shared point (before SHA-256) for debugging */
int zkn_sw_ed25519_scalarmul(const u8 scalar_le[32], const u8 VK[32], u8 out[32]){ gf P[4],Q[4]; if(unpack(Q,VK)) return -1; scalarmult(P,Q,scalar_le); pack(out,P); return 0; }

