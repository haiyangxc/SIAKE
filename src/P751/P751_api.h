 

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


#define KEX_A_PUBLICKEYBYTES      1160      //public bytes that  A sends to B=CRYPTO_PUBLICKEYBYTES + CRYPTO_CIPHERTEXTBYTES
#define KEX_B_PUBLICKEYBYTES      596       //public bytes that  B sends to A=CRYPTO_CIPHERTEXTBYTES

#define KEX_BYTES                 32        //The bytes of session key 

#define CRYPTO_SECRETKEYBYTES     644    // MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes
#define CRYPTO_PUBLICKEYBYTES     564
#define CRYPTO_CIPHERTEXTBYTES    596    // CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes
#define SECRETKEY_A_BYTES 47
#define SECRETKEY_B_BYTES 48
#define MSG_BYTES         32


/**********Regist  Phase**************/
// SIAKE's user registration
// It produces a static private key sk and computes the public key pk.
// Outputs: static secret key sk (CRYPTO_SECRETKEYBYTES = 47 or 48 bytes)
//          static public key pk (CRYPTO_PUBLICKEYBYTES = 564 bytes) 

int AKE_registA(unsigned char *sPrivateKeyA, unsigned char *sPublicKeyA);
int AKE_registB(unsigned char *sPrivateKeyB, unsigned char *sPublicKeyB);

/*As a initiator A generates ephemeral public key ePublicKeyA0, *
*ciphertext ciphertextA1 under B's public key sPublicKeyB*      *
*and send-----ciphertextA1, ePublicKeyA0----------> to B        *
* A keeps sPrivateKeyA, KeyA1 for next round*
**/
int AKE_initA(unsigned char* ciphertextA1, unsigned char* ePublicKeyA2, unsigned char* KeyA1, unsigned char*ePrivateKeyA2, const unsigned char* sPrivateKeyA, const unsigned char* sPublicKeyB);


/*On receiving ePublicKeyA0, ciphertextA1 form A, the responder B  *
*decapsulated KeyA_ coresponding to ciphertextA1, computes ciphertext  *
*under public keys sPublicKeyA and ePublicKeyA0, and the corresponding KeyB *
*       A <------ciphertextB------------- B
* Generates the final session key SharedSecretB*
**/
int AKE_kdfB(unsigned char* SharedSecretB, unsigned char* ciphertextB, const unsigned char* sPrivateKeyB, const unsigned char* sPublicKeyA, const  unsigned char* ePublicKeyA2, const  unsigned char* ciphertextA1);

/*On receiving ciphertextB from B, A  *
*decapsulated KeyB_ coresponding to ciphertextB, computes  *
* the final session key SharedSecretA*
**/
int Ake_kdfA(unsigned char* SharedSecretA, const unsigned char* KeyA1, const unsigned char* sPrivateKeyA, const unsigned char* ePrivateKeyA2, const unsigned char* ciphertextB);




#endif