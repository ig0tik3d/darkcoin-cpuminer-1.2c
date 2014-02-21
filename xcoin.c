#include "cpuminer-config.h"
#include "miner.h"


#include <string.h>
#include <stdint.h>

//--
#include "x5/luffa_for_sse2.h" //sse2 opt
//----
#include "x5/cubehash_sse2.h" //sse2 opt
//--------------------------
#include "x5/sph_shavite.h"
//-----simd vect128---------
#include "x5/vect128/nist.h"
//-----------

#define AES_NI
//#define AES_NI_GR

#ifdef AES_NI
#include "x5/echo512/ccalik/aesni/hash_api.h"
#else
#include "x5/sph_echo.h"
#endif


//----
#include "x6/blake.c"
//#include "x5/blake/sse41/hash.c"
#include "x6/bmw.c"
#include "x6/keccak.c"
#include "x6/skein.c"
#include "x6/jh_sse2_opt64.h"
//#include "groestl.c"
#ifdef AES_NI_GR
#include "x6/groestl/aesni/hash-groestl.h"
#else
#if 1
#include "x6/grso.c"
#ifndef PROFILERUN
#include "x6/grso-asm.c"
#endif
#else
#include "x6/grss_api.h"
#endif
#endif  //AES-NI_GR


/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGNXY(x,y) x __attribute__ ((aligned(y)))
#else
#define DATA_ALIGNXY(x,y) __declspec(align(y)) x
#endif

#ifdef AES_NI
typedef struct {
	sph_shavite512_context  shavite1;
	hashState_echo		echo1;
	hashState_groestl groestl;
	hashState_luffa luffa;
	cubehashParam cubehash;
	hashState_sd ctx_simd1;
//	hashState_blake	blake1;
} Xhash_context_holder;
#else
typedef struct {
	sph_shavite512_context  shavite1;
	sph_echo512_context		echo1;
	hashState_luffa	luffa;
	cubehashParam	cubehash;
	hashState_sd ctx_simd1;
//	hashState_blake	blake1;
} Xhash_context_holder;
#endif

Xhash_context_holder base_contexts;


void init_Xhash_contexts(){

	//---luffa---
	init_luffa(&base_contexts.luffa,512);
	//--ch sse2---
	cubehashInit(&base_contexts.cubehash,512,16,32);
	//-------
	sph_shavite512_init(&base_contexts.shavite1);
	//---echo sphlib or AESNI-----------
	#ifdef AES_NI
  	init_echo(&base_contexts.echo1, 512);
	#else
	sph_echo512_init(&base_contexts.echo1);
	#endif
	//---local simd var ---
	init_sd(&base_contexts.ctx_simd1,512);
}

inline void Xhash(void *state, const void *input)
{
	Xhash_context_holder ctx;

//	uint32_t hashA[16], hashB[16];


	memcpy(&ctx, &base_contexts, sizeof(base_contexts));
	#ifdef AES_NI_GR
	init_groestl(&ctx.groestl);
	#endif

	DATA_ALIGNXY(unsigned char hashbuf[128],16);
	size_t hashptr;
	DATA_ALIGNXY(sph_u64 hashctA,8);
	DATA_ALIGNXY(sph_u64 hashctB,8);

	#ifndef AES_NI_GR
	grsoState sts_grs;
	#endif


	DATA_ALIGNXY(unsigned char hash[128],16);
	/* proably not needed */
	memset(hash, 0, 128);
	//blake1-bmw2-grs3-skein4-jh5-keccak6-luffa7-cubehash8-shavite9-simd10-echo11
	//---blake1---
/*
