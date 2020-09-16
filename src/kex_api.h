

/********************************************************************************************
*
*       SIAKE API. the code is based on  SIDH: an efficient supersingular isogeny cryptography library
*       by Xue Haiyang and Xu Xiu
* Abstract: API header file for SIAKEp751
*********************************************************************************************/

#ifndef __P751_API_H__
#define __P751_API_H__


/*********************** AKE API ***********************/

// Algorithm name
#define KEX_ALGNAME "SIAKEp751"  

#define KEX_s_A_SECRETKEYBYTES    47      //static secret key bytes of A =
#define KEX_s_B_SECRETKEYBYTES    48      //static secret key bytes of A
#define KEX_e_A_SECRETKEYBYTES    47      //ephemeral secret key bytes of A
#define KEX_e_B_SECRETKEYBYTES    48      //ephemeral secret key bytes of A

#define KEX_s_A_PUBLICKEYBYTES    564      //static public key bytes of A=CRYPTO_PUBLICKEYBYTES
#define KEX_s_B_PUBLICKEYBYTES    564      //static public key bytes of B=CRYPTO_PUBLICKEYBYTES


#define KEX_A_PUBLICBYTES      1160      //public bytes that  A sends to B=CRYPTO_PUBLICKEYBYTES + CRYPTO_CIPHERTEXTBYTES
#define KEX_B_PUBLICBYTES      596       //public bytes that  B sends to A=CRYPTO_CIPHERTEXTBYTES

#define KEX_BYTES                 32        //The bytes of session key 

#define CRYPTO_SECRETKEYBYTES     644    // MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes
#define CRYPTO_PUBLICKEYBYTES     564
#define CRYPTO_CIPHERTEXTBYTES    596    // CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes
#define SECRETKEY_A_BYTES 47
#define SECRETKEY_B_BYTES 48
#define MSG_BYTES         32


unsigned long long rand_get_sd_byts();
int rand_init(unsigned char * s, unsigned long long s_byts);
int rand_byts(unsigned long long r_byts, unsigned char * r);

unsigned long long kex_get_rounds();

unsigned long long kex_get_pk_byts();

unsigned long long kex_get_sk_byts();
unsigned long long kex_get_pa_byts();
unsigned long long kex_get_pb_byts();


unsigned long long kex_get_ss_byts();

unsigned long long kex_get_bw_byts();



int kex_init_a(unsigned char * pk, unsigned long long * pk_byts, unsigned char * sk, unsigned long long * sk_byts, unsigned char * pa, unsigned long long * pa_byts);
int kex_init_b(unsigned char * pk, unsigned long long * pk_byts, unsigned char * sk, unsigned long long * sk_byts, unsigned char * pb, unsigned long long * pb_byts);
int kex_send_a(unsigned char * pkb, unsigned long long pkb_byts, unsigned char * pa, unsigned long long * pa_byts, unsigned char * ma, unsigned long long * ma_byts);
int kex_send_b(unsigned char * pka, unsigned long long pka_byts, unsigned char * ma, unsigned long long ma_byts, unsigned char * pb, unsigned long long * pb_byts, unsigned char * mb, unsigned long long * mb_byts, unsigned char * ss, unsigned long long * ss_byts);
int kex_resp_a(unsigned char * mb, unsigned long long mb_byts, unsigned char * pa, unsigned long long * pa_byts, unsigned char * ma, unsigned long long * ma_byts, unsigned char * ss, unsigned long long * ss_byts);



#endif