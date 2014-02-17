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
/*
#if 1
#include "x6/grso.c"
#ifndef PROFILERUN
#include "x6/grso-asm.c"
#endif
#else
#include "x6/grss_api.h"
#endif
 */
#include "x6/groestl/aesni/hash-groestl.h"
/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

#ifdef AES_NI
typedef struct {
	sph_shavite512_context  shavite1;
	//sph_simd512_context		simd1;
	hashState_echo		echo1;
	hashState_groestl groestl;
	hashState_luffa luffa;
	cubehashParam cubehash;
//	hashState_blake	blake1;
} Xhash_context_holder;
#else
typedef struct {
	sph_shavite512_context  shavite1;
	//sph_simd512_context		simd1;
	sph_echo512_context		echo1;
//	hashState_blake	blake1;
} Xhash_context_holder;
#endif
Xhash_context_holder base_contexts;


void init_Xhash_contexts()
{
   //---luffa---
  init_luffa(&base_context.luffa,512);
  //--ch sse2---
  cubehashInit(&base_context.cubehash,512,16,32);
  //-------
  sph_shavite512_init(&base_contexts.shavite1);
  //---simd---
  //sph_simd512_init(&base_contexts.simd1); 
  //--------------
  #ifdef AES_NI
  init_echo(&base_contexts.echo1, 512);
  init_groestl(&base_contexts.groestl);
  #else
  sph_echo512_init(&base_contexts.echo1);
  #endif

}

inline void Xhash(void *state, const void *input)
{
	Xhash_context_holder ctx;
//	hashState_luffa			 ctx_luffa;
//	cubehashParam		 ctx_cubehash;
	//---local simd var ---
	hashState_sd *     ctx_simd1;
	
	uint32_t hashA[16], hashB[16];	

//	memcpy(&ctx_luffa,&base_context_luffa,sizeof(hashState_luffa));
//	memcpy(&ctx_cubehash,&base_context_cubehash,sizeof(cubehashParam));
	
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));
    
	DATA_ALIGN16(unsigned char hashbuf[128]);
    DATA_ALIGN16(size_t hashptr);
    DATA_ALIGN16(sph_u64 hashctA);
    DATA_ALIGN16(sph_u64 hashctB);

	
//    grsoState sts_grs;
   
    int speedrun[] = {0, 1, 3, 4, 6, 7 };
    int i;
    DATA_ALIGN16(unsigned char hash[128]);
    /* proably not needed */
    memset(hash, 0, 128);
// blake1-bmw2-grs3-skein4-jh5-keccak6-luffa7-cubehash8-shavite9-simd10-echo11
	//---blake1---
/*	  //blake init
    blake512_init(&base_contexts.blake1, 512);
	blake512_update(&ctx.blake1, input, 512);
	blake512_final(&ctx.blake1, hash);
*/
    DECL_BLK;
    BLK_I;
    BLK_W;
    BLK_C;

//---bmw2---
	DECL_BMW;
	BMW_I;
	BMW_U;
	#define M(x)    sph_dec64le_aligned(data + 8 * (x))
	#define H(x)    (h[x])
	#define dH(x)   (dh[x])
        BMW_C;
	#undef M
	#undef H
	#undef dH
//---grs3 ---
	update_groestl(&ctx.groestl, (char*)hash,512);
	final_groestl(&ctx.groestl, (char*)hash);
/*
	GRS_I;
	GRS_U;
	GRS_C;
*/
//---skein4---          
	DECL_SKN;
	SKN_I;
	SKN_U;
	SKN_C; 
//---jh5---            
	DECL_JH;
	JH_H;
//---keccak6---       
	DECL_KEC;
	KEC_I;
	KEC_U;
	KEC_C;


 asm volatile ("emms");
 

		    
    //--- luffa7	
	update_luffa(&ctx.luffa,(const BitSequence*)hash,512);
	final_luffa(&ctx.luffa,(BitSequence*)hashA);	
	//---cubehash---    
	cubehashUpdate(&ctx.cubehash,(const byte*)hashA,64);
	cubehashDigest(&ctx.cubehash,(byte*)hashB);
	//---shavite---
    sph_shavite512 (&ctx.shavite1, hashB, 64);   
    sph_shavite512_close(&ctx.shavite1, hashA);
	//sph_simd512 (&ctx.simd1, hashA, 64);   
    // sph_simd512_close(&ctx.simd1, hashB); 
    //-------simd512 vect128 --------------	
	ctx_simd1=malloc(sizeof(hashState_sd));
	Init(ctx_simd1,512);
	Update(ctx_simd1,(const BitSequence *)hashA,512);
	Final(ctx_simd1,(BitSequence *)hashB);  
	free(ctx_simd1->buffer);
	free(ctx_simd1->A);
	free(ctx_simd1);
	//---echo---
	#ifdef AES_NI
	update_echo (&ctx.echo1,(const BitSequence *) hashB, 512);   
	final_echo(&ctx.echo1, (BitSequence *) hashA); 
	#else
	sph_echo512 (&ctx.echo1, hashB, 64);
    sph_echo512_close(&ctx.echo1, hashA); 
	#endif
 
    memcpy(state, hashA, 32);
}

int scanhash_X(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	       uint32_t n = pdata[19] - 1;
        const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];

        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t endiandata[32];
        
        
        int kk=0;
        for (; kk < 32; kk++)
        {
                be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
        };
        if (ptarget[7]==0) {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFFFF)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        else if (ptarget[7]<=0xF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFFF0)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        else if (ptarget[7]<=0xFF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFF00)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        else if (ptarget[7]<=0xFFF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFF000)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        

        }
        else if (ptarget[7]<=0xFFFF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFF0000)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        

        }
        else
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);        
        }
        
        
        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}
