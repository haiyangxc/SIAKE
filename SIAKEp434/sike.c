/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/ 

#include <string.h>
#include "sha3/fips202.h"


int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{ // SIKE's key generation of Bob
  // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          public key pk (CRYPTO_PUBLICKEYBYTES bytes) 

    // Generate lower portion of secret key sk <- s||SK
    randombytes(sk, MSG_BYTES);
    random_mod_order_B(sk + MSG_BYTES);

    // Generate public key pk
    EphemeralKeyGeneration_B(sk + MSG_BYTES, pk);

    // Append public key pk to secret key sk
    memcpy(&sk[MSG_BYTES + SECRETKEY_B_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

    return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // SIKE's encapsulation
  // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
  // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
  //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    unsigned char ephemeralsk[SECRETKEY_A_BYTES];
    unsigned char jinvariant[FP2_ENCODED_BYTES];
    unsigned char h[MSG_BYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES+MSG_BYTES];

    // Generate ephemeralsk <- G(m||pk) mod oA 
    randombytes(temp, MSG_BYTES);
    memcpy(&temp[MSG_BYTES], pk, CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES+MSG_BYTES);
    ephemeralsk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Encrypt
    EphemeralKeyGeneration_A(ephemeralsk, ct);
    EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);
    shake256(h, MSG_BYTES, jinvariant, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        ct[i + CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];
    }

    // Generate shared secret ss <- H(m||ct)
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES+MSG_BYTES);

    return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // SIKE's decapsulation
  // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes) 
  // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    unsigned char ephemeralsk_[SECRETKEY_A_BYTES];
    unsigned char jinvariant_[FP2_ENCODED_BYTES];
    unsigned char h_[MSG_BYTES];
    unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES+MSG_BYTES];

    // Decrypt
    EphemeralSecretAgreement_B(sk + MSG_BYTES, ct, jinvariant_);
    shake256(h_, MSG_BYTES, jinvariant_, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        temp[i] = ct[i + CRYPTO_PUBLICKEYBYTES] ^ h_[i];
    }

    // Generate ephemeralsk_ <- G(m||pk) mod oA
    memcpy(&temp[MSG_BYTES], &sk[MSG_BYTES + SECRETKEY_B_BYTES], CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk_, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES+MSG_BYTES);
    ephemeralsk_[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;
    
    // Generate shared secret ss <- H(m||ct), or output ss <- H(s||ct) in case of ct verification failure
    EphemeralKeyGeneration_A(ephemeralsk_, c0_);
    // If selector = 0 then do ss = H(m||ct), else if selector = -1 load s to do ss = H(s||ct)
    int8_t selector = ct_compare(c0_, ct, CRYPTO_PUBLICKEYBYTES);
    ct_cmov(temp, sk, MSG_BYTES, selector);
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES+MSG_BYTES);

    return 0;
}


int crypto_2kem_keypairA(unsigned char *pk, unsigned char *sk)
{ // SIKE's key generation of Alice
  // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_A_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          public key pk (CRYPTO_PUBLICKEYBYTES bytes) 

    // Generate lower portion of secret key sk <- s||SK
    randombytes(sk, MSG_BYTES);
    random_mod_order_A(sk + MSG_BYTES);

    // Generate public key pk
    EphemeralKeyGeneration_A(sk + MSG_BYTES, pk);

    // Append public key pk to secret key sk
    memcpy(&sk[MSG_BYTES + SECRETKEY_A_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

    return 0;
}



int crypto_2kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pkA, const unsigned char *pkA0)
{ // SIKE's encapsulation
  // Input:   static and ephemeral public keys pkA and pkA0   (CRYPTO_PUBLICKEYBYTES bytes)
  // Outputs: shared secret ss                                (CRYPTO_BYTES bytes)
  //          ciphertext message ct                           (CRYPTO_CIPHERTEXTBYTES + MSG_BYTES = CRYPTO_PUBLICKEYBYTES + 2*MSG_BYTES bytes)
  
  
    unsigned char ephemeralsk[SECRETKEY_B_BYTES];
    unsigned char jinvariant1[FP2_ENCODED_BYTES];
	unsigned char jinvariant2[FP2_ENCODED_BYTES];
    unsigned char h[MSG_BYTES];
    unsigned char temp[2*CRYPTO_PUBLICKEYBYTES+3*MSG_BYTES];

    // Generate ephemeralsk <- G(m1||m2||pkA||pkA0) mod oA 
    randombytes(temp, 2*MSG_BYTES);
    memcpy(&temp[2*MSG_BYTES], pkA, CRYPTO_PUBLICKEYBYTES);
    memcpy(&temp[2*MSG_BYTES+CRYPTO_PUBLICKEYBYTES], pkA0, CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk, SECRETKEY_B_BYTES, temp, 2*CRYPTO_PUBLICKEYBYTES+2*MSG_BYTES);
    ephemeralsk[SECRETKEY_B_BYTES - 1] &= MASK_BOB;

    // Encrypt
    EphemeralKeyGeneration_B(ephemeralsk, ct);
    EphemeralSecretAgreement_B(ephemeralsk, pkA, jinvariant1);

	
    shake256(h, MSG_BYTES, jinvariant1, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        ct[i + CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];
    }
    EphemeralSecretAgreement_B(ephemeralsk, pkA0, jinvariant2);
    shake256(h, MSG_BYTES, jinvariant2, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        ct[i + CRYPTO_PUBLICKEYBYTES + MSG_BYTES] = temp[i+MSG_BYTES] ^ h[i];
    }

    // Generate shared secret ss <- H(m1||m2||ct)
    memcpy(&temp[2*MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES + 3*MSG_BYTES);

    return 0;
}


int crypto_2kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *skA, const unsigned char *skA0)
{ // SIKE's decapsulation
  // Input:   static and epemeral secret keys skA, skA0         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_A_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          ciphertext message ct                             (CRYPTO_CIPHERTEXTBYTES + MSG_BYTES = CRYPTO_PUBLICKEYBYTES + 2*MSG_BYTES bytes) 
  // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    unsigned char ephemeralsk_[SECRETKEY_B_BYTES];
    unsigned char jinvariant1_[FP2_ENCODED_BYTES];
	unsigned char jinvariant2_[FP2_ENCODED_BYTES];
    unsigned char h_[MSG_BYTES];
    unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
    unsigned char temp[2*CRYPTO_PUBLICKEYBYTES+3*MSG_BYTES];

    // Decrypt
    EphemeralSecretAgreement_A(skA + MSG_BYTES, ct, jinvariant1_);
    shake256(h_, MSG_BYTES, jinvariant1_, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        temp[i] = ct[i + CRYPTO_PUBLICKEYBYTES] ^ h_[i];
    }
	EphemeralSecretAgreement_A(skA0 + MSG_BYTES, ct, jinvariant2_);
    shake256(h_, MSG_BYTES, jinvariant2_, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        temp[i + MSG_BYTES] = ct[i + CRYPTO_PUBLICKEYBYTES + MSG_BYTES] ^ h_[i];
    }
	
	
    // Generate ephemeralsk_ <- G(m1||m||2||pkA||pkA0) mod oA
    memcpy(&temp[2*MSG_BYTES], &skA[MSG_BYTES + SECRETKEY_A_BYTES], CRYPTO_PUBLICKEYBYTES);
	memcpy(&temp[2*MSG_BYTES+CRYPTO_PUBLICKEYBYTES], &skA0[MSG_BYTES + SECRETKEY_A_BYTES], CRYPTO_PUBLICKEYBYTES);
	
    shake256(ephemeralsk_, SECRETKEY_B_BYTES, temp, 2*CRYPTO_PUBLICKEYBYTES+2*MSG_BYTES);
    ephemeralsk_[SECRETKEY_B_BYTES - 1] &= MASK_BOB;

  
    // Generate shared secret ss <- H(m1||m2||ct), or output ss <- H(s||ct) in case of ct verification failure
    EphemeralKeyGeneration_B(ephemeralsk_, c0_);
    // If selector = 0 then do ss = H(m||ct), else if selector = -1 load s to do ss = H(s||ct)
    int8_t selector = ct_compare(c0_, ct, CRYPTO_PUBLICKEYBYTES);
    ct_cmov(temp, skA, MSG_BYTES, selector);
	ct_cmov(temp + MSG_BYTES, skA0, MSG_BYTES, selector);
    memcpy(&temp[2*MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES+MSG_BYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES + 3*MSG_BYTES);

    return 0;
}
