/********************************************************************************************
* Modified based on SIDH: an efficient supersingular isogeny cryptography library
* by 薛海洋，徐秀，贺婧楠
* Abstract: SIAKE 基础算法
* 参考文献：附件一，附件二，附件三
*********************************************************************************************/

#include <string.h>
#include "sha3/fips202.h"

//random functin
unsigned long long rand_get_sd_byts() {

	return 48;//bytes of init seed
}

int rand_init(unsigned char * s, unsigned long long s_byts) {

	randombytes_init(s, NULL, 256);
	return 0;
}

int rand_byts(unsigned long long r_byts, unsigned char * r) {

	randombytes(r, r_byts);
	return 0;
}


//1-key KEM 其中一个公钥设为0的2-key KEM
int crypto_kem_kgen1(unsigned char *sPrivateKeyB, unsigned char *sPublicKeyB)
{
	random_mod_order_B(sPrivateKeyB);
	EphemeralKeyGeneration_B(sPrivateKeyB, sPublicKeyB);
}

int crypto_kem_enc1(unsigned char *ciphertextA1, unsigned char *KeyA1, const unsigned char*tempR, const unsigned char *sPublicKeyB)
{ //Internal SIKE-1-key encapsulation under public key of B
  // Input:   public key of B    sPublicKeyB        (CRYPTO_PUBLICKEYBYTES bytes)
  //		  secret key of A    sPrivateKeyA  (SECRETKEY_A_BYTES)
  // Outputs: encapsulated key  (keyA1)    (CRYPTO_BYTES bytes)
  //          ciphertext message ciphertextA1 (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes) 
	const uint16_t f = 0;
	const uint16_t G = 1;
	const uint16_t h = 2;
	const uint16_t H = 3;
	unsigned char ephemeralsk[SECRETKEY_A_BYTES];
	unsigned char jinvariant[FP2_ENCODED_BYTES];
	unsigned char hj[MSG_BYTES];
	//unsigned char temp[SECRETKEY_A_BYTES + MSG_BYTES];
	unsigned int i;
	//unsigned char tempm[MSG_BYTES];
	// Generate ephemeral m <- f(r||sk_A) mod oA 
	//randombytes(temp, MSG_BYTES); //r
//	memcpy(&temp[MSG_BYTES], sPrivateKeyA, SECRETKEY_A_BYTES);//temp=r||sk_A
//	cshake256_simple(tempm, MSG_BYTES, f, temp, SECRETKEY_A_BYTES + MSG_BYTES);//tempm=f(r||sk_A)
	cshake256_simple(ephemeralsk, SECRETKEY_A_BYTES, G, tempR, MSG_BYTES);//ephemeralsk=G(tempm)

	//for (i = MSG_BYTES; i < SECRETKEY_A_BYTES; i++) ephemeralsk[i] = 0;
	ephemeralsk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

	// Encrypt
	EphemeralKeyGeneration_A(ephemeralsk, ciphertextA1);  //g^ephemeralsk 
	EphemeralSecretAgreement_A(ephemeralsk, sPublicKeyB, jinvariant); //jinvariant of E_A0B
	cshake256_simple(hj, MSG_BYTES, h, jinvariant, FP2_ENCODED_BYTES);
	for (i = 0; i < MSG_BYTES; i++)
	{
		ciphertextA1[i + CRYPTO_PUBLICKEYBYTES] = tempR[i] ^ hj[i];//ciphertextA2=h(jinvariant)

	}
	cshake256_simple(KeyA1, MSG_BYTES, H, tempR, MSG_BYTES);// K:=H(m)
	return 0;
}

int crypto_kem_dec1(unsigned char *KeyA1, const unsigned char *ciphertextA1, const unsigned char *sPrivateKeyB)
{ // Internal SIKE-1-key-decapsulation using secret key of B
  // Input:   secret key sPrivateKeyB     (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          ciphertext message    ciphertextA1   (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes) 
  // Outputs: encapsulated key  KeyA1           (CRYPTO_BYTES bytes)
	const uint16_t f = 0;
	const uint16_t G = 1;
	const uint16_t h = 2;
	const uint16_t H = 3;

	unsigned char ephemeralsk_[SECRETKEY_A_BYTES];
	unsigned char jinvariant_[FP2_ENCODED_BYTES];
	unsigned char hj_[MSG_BYTES];
	unsigned char ciphertextA1_[CRYPTO_PUBLICKEYBYTES];
	unsigned char c0_[CRYPTO_PUBLICKEYBYTES];

	unsigned int i;
	unsigned char tempm[MSG_BYTES];
	bool passed = true;

	for (int j = 0; j < CRYPTO_PUBLICKEYBYTES; j++)
	{
		ciphertextA1_[j] = ciphertextA1[j];

	}
	// Decrypt
	EphemeralSecretAgreement_B(sPrivateKeyB, ciphertextA1_, jinvariant_);  //j
	cshake256_simple(hj_, MSG_BYTES, h, jinvariant_, FP2_ENCODED_BYTES); // h(j)
	for (i = 0; i < MSG_BYTES; i++) tempm[i] = ciphertextA1[i + CRYPTO_PUBLICKEYBYTES] ^ hj_[i]; //m

	cshake256_simple(ephemeralsk_, SECRETKEY_A_BYTES, G, tempm, MSG_BYTES); // ephemeralsk_=G(m)
	//for (i = MSG_BYTES; i < SECRETKEY_A_BYTES; i++) ephemeralsk_[i] = 0;
	ephemeralsk_[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

	// check if c0_=g^ephemeralsk_=ciphertextA1
	EphemeralKeyGeneration_A(ephemeralsk_, c0_);
	if (memcmp(c0_, ciphertextA1, CRYPTO_PUBLICKEYBYTES) != 0) {

		passed = false;
		//	printf("crypto_kem_dec failed");
	}

	cshake256_simple(KeyA1, MSG_BYTES, H, tempm, MSG_BYTES);// K:=H(m||sk_A)
	return 0;
}

//2-key KEM 
int ckem_enc_kgen(unsigned char *sPrivateKeyA, unsigned char *sPublicKeyA, unsigned char *sPrivateKeyA0, unsigned char *sPublicKeyA0)
{
	random_mod_order_A(sPrivateKeyA);
	EphemeralKeyGeneration_A(sPrivateKeyA, sPublicKeyA);
	random_mod_order_A(sPrivateKeyA0);
	EphemeralKeyGeneration_A(sPrivateKeyA0, sPublicKeyA0);
}


int ckem_enc(unsigned char *ciphertextB, unsigned char *KeyB, const  unsigned char *sPublicKeyA, const  unsigned char *ePublicKeyA2, const unsigned char *tempm)
{//Internal SIKE-2-key encapsulation under public key of sPublicKeyA and ePublicKeyA2
  // Input:   static public key of A    sPublicKeyA        (CRYPTO_PUBLICKEYBYTES bytes)
  //		  epemeral public key of A    ePublicKeyA        (CRYPTO_PUBLICKEYBYTES bytes)
  //	      secret key of B    sPrivateKeyB  (SECRETKEY_B_BYTES)
  // Outputs: encapsulated key  (keyB)    (CRYPTO_BYTES bytes)
  //          ciphertext message ciphertextB (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes) 
	const uint16_t f = 0;
	const uint16_t G = 1;
	const uint16_t h = 2;
	const uint16_t H = 3;
	//	const uint16_t Y = 3;

	//unsigned char temp[MSG_BYTES + SECRETKEY_B_BYTES];
	unsigned int  i;
	//unsigned char m_1[MSG_BYTES];
	//unsigned char m_2[MSG_BYTES];
	unsigned char ephemeralsk[SECRETKEY_B_BYTES];
	//unsigned char tempm[MSG_BYTES*2];
	unsigned char j1[FP2_ENCODED_BYTES];
	unsigned char j2[FP2_ENCODED_BYTES];
	unsigned char hj1[MSG_BYTES];
	unsigned char hj2[MSG_BYTES];

	//randombytes(tempm, MSG_BYTES*2);    //r_A
//	memcpy(&temp[MSG_BYTES], sPrivateKeyB, SECRETKEY_B_BYTES);   //temp=r_A||sk_B
//	cshake256_simple(tempm, MSG_BYTES, f, temp, MSG_BYTES); //  tempm=f(temp)


	cshake256_simple(ephemeralsk, SECRETKEY_B_BYTES, G, tempm, MSG_BYTES*2); //ephemeralsk=G(m)


	EphemeralKeyGeneration_B(ephemeralsk, ciphertextB);  //g^ephemeralsk
	EphemeralSecretAgreement_B(ephemeralsk, sPublicKeyA, j1);
	EphemeralSecretAgreement_B(ephemeralsk, ePublicKeyA2, j2);

	//memcpy(&j2[FP2_ENCODED_BYTES], &j1, FP2_ENCODED_BYTES);
	cshake256_simple(hj1, MSG_BYTES, h, j1, FP2_ENCODED_BYTES);
	cshake256_simple(hj2, MSG_BYTES, h, j2, FP2_ENCODED_BYTES);

	for (i = 0; i < MSG_BYTES; i++)
		ciphertextB[i + CRYPTO_PUBLICKEYBYTES] = hj1[i] ^ tempm[i];

	for (i = 0; i < MSG_BYTES; i++)
		ciphertextB[i + CRYPTO_PUBLICKEYBYTES+ MSG_BYTES] = hj2[i] ^ tempm[i+ MSG_BYTES];

	cshake256_simple(KeyB, MSG_BYTES, H, tempm, MSG_BYTES*2);// K:=H(m)
	return 0;
}

int ckem_dec(unsigned char *KeyB, const unsigned char *ciphertextB, const unsigned char *sPrivateKeyA, const unsigned char *ePrivateKeyA2)
{
	//Internal SIKE-2-key decapsulation under secret key of sPrivateKeyA and ePrivateKeyA2
	// Input:  static secret key of A    sPrivateA        (SECRETKEY_A_BYTES bytes)
	//		  epemeral secret key of A    ePrivateA2        (SECRETKEY_A_BYTES bytes)
	//	      ciphertext of B    sPrivateKeyB  (CRYPTO_CIPHERTEXTBYTESCRYPTO_PUBLICKEYBYTES+MSG_BYTES)
	// Outputs: encapsulated key  (keyB)    (CRYPTO_BYTES bytes)
	//           

	const uint16_t f = 0;
	const uint16_t G = 1;
	const uint16_t h = 2;
	const uint16_t H = 3;
	//	const uint16_t Y = 3;
	unsigned int i;
	unsigned char ciphertextB_[CRYPTO_PUBLICKEYBYTES];
	unsigned char ephemeralsk[SECRETKEY_B_BYTES];
	unsigned char tempm[MSG_BYTES*2];
	unsigned char j1[FP2_ENCODED_BYTES];
	unsigned char j2[FP2_ENCODED_BYTES];
	unsigned char hj1[MSG_BYTES];
	unsigned char hj2[MSG_BYTES];

	unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
	bool passed = true;

	for (int j = 0; j < CRYPTO_PUBLICKEYBYTES; j++)
	{
		ciphertextB_[j] = ciphertextB[j];
	}


	EphemeralSecretAgreement_A(sPrivateKeyA, ciphertextB_, j1);
	EphemeralSecretAgreement_A(ePrivateKeyA2, ciphertextB_, j2);
	//memcpy(&j2[FP2_ENCODED_BYTES], &j1, FP2_ENCODED_BYTES);
	cshake256_simple(hj1, MSG_BYTES, h, j1, FP2_ENCODED_BYTES);
	cshake256_simple(hj2, MSG_BYTES, h, j2, FP2_ENCODED_BYTES);

	for (i = 0; i < MSG_BYTES; i++) tempm[i] = ciphertextB[i + CRYPTO_PUBLICKEYBYTES] ^ hj1[i];//m
	for (i = 0; i < MSG_BYTES; i++) tempm[i+ MSG_BYTES] = ciphertextB[i + CRYPTO_PUBLICKEYBYTES+ MSG_BYTES] ^ hj2[i];//m

	cshake256_simple(ephemeralsk, SECRETKEY_B_BYTES, G, tempm, MSG_BYTES*2);  //G(m)

	EphemeralKeyGeneration_B(ephemeralsk, c0_);

	if (memcmp(c0_, ciphertextB_, CRYPTO_PUBLICKEYBYTES) != 0)
	{
		passed = false;
	}
	cshake256_simple(KeyB, MSG_BYTES, H, tempm, MSG_BYTES*2);// K:=H(m)
	return 0;
}




unsigned long long kex_get_rounds()
{
	return 2;
}




unsigned long long kex_get_pk_byts()
{
	return 564;
}
unsigned long long kex_get_sk_byts()
{
	return 48;
}

unsigned long long kex_get_pa_byts()
{
	return 126;
}

unsigned long long kex_get_pb_byts()
{
	return 48;
}

unsigned long long kex_get_ss_byts()
{
	return 32;
}

unsigned long long kex_get_bw_byts()
{
	return 1788;
}


int kex_init_a(unsigned char * pk, unsigned long long * pk_byts, unsigned char * sk, unsigned long long * sk_byts, unsigned char * pa, unsigned long long * pa_byts)
{
	unsigned long long r_byts = 128;
	unsigned char randomstring[128] = { 0 };

	rand_byts(47, sk);
	sk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;
	
	//random_mod_order_A(sPrivateKeyA);
	EphemeralKeyGeneration_A(sk, pk);
	
	memcpy(pa, sk, 47);
	
	
	*pk_byts = 564;
	*sk_byts = 47;
	*pa_byts = 47;

	return 0;


}



int kex_init_b(unsigned char * pk, unsigned long long * pk_byts, unsigned char * sk, unsigned long long * sk_byts, unsigned char * pb, unsigned long long * pb_byts)
{

	rand_byts(48, sk);

	sk[SECRETKEY_B_BYTES - 1] &= MASK_BOB;

	//random_mod_order_B(sPrivateKeyB);
	EphemeralKeyGeneration_B(sk, pk);
	memcpy(pb, sk, 48);
	*pk_byts = 564;
	*sk_byts = 48;
	*pb_byts = 48;
	return 0;
}

int kex_send_a(unsigned char * pkb, unsigned long long pkb_byts, unsigned char * pa, unsigned long long * pa_byts, unsigned char * ma, unsigned long long * ma_byts)
{
	unsigned char ciphertextA1[596] = { 0 };
	unsigned char ePublicKeyA2[564] = { 0 };
	unsigned char ePrivateKeyA2[47] = { 0 };
	unsigned char Tempm_A[32] = { 0 };
	unsigned char KeyA1[32] = { 0 };

	rand_byts(32, Tempm_A);


	crypto_kem_enc1(ciphertextA1, KeyA1, Tempm_A, pkb);
	rand_byts(47, ePrivateKeyA2);
	
	ePrivateKeyA2[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;
	
	//random_mod_order_A(ePrivateKeyA2);
	EphemeralKeyGeneration_A(ePrivateKeyA2, ePublicKeyA2);
	memcpy(pa + 47, ePrivateKeyA2, 47);//ePrivateKeyA2=pa[47-93]
	memcpy(pa+94, KeyA1, 32);//pa[94-125]=KeyA1
	memcpy(ma, ciphertextA1, CRYPTO_CIPHERTEXTBYTES);
	memcpy(ma+ CRYPTO_CIPHERTEXTBYTES, ePublicKeyA2, CRYPTO_PUBLICKEYBYTES);

	*pa_byts = 126;
	*ma_byts = 1160;
	return 0;

}





int KEX_kdfB(unsigned char* SharedSecretB, unsigned char* tempm, unsigned char* ciphertextB, const unsigned char* sPrivateKeyB, const unsigned char* sPublicKeyA, const  unsigned char* ePublicKeyA2, const  unsigned char* ciphertextA1)
{
	const uint16_t T = 4;
	unsigned char temp[MSG_BYTES * 2] = { 0 };
	//unsigned char KeyA1[MSG_BYTES] = { 0 };
	unsigned char KeyB[MSG_BYTES] = { 0 };
	unsigned char KeyA11[MSG_BYTES] = { 0 };
	

	
	ckem_enc(ciphertextB, KeyB, sPublicKeyA, ePublicKeyA2, tempm);

	crypto_kem_dec1(KeyA11, ciphertextA1, sPrivateKeyB);

	memcpy(&temp[0], KeyB, MSG_BYTES);
	memcpy(&temp[MSG_BYTES], KeyA11, MSG_BYTES);
	cshake256_simple(SharedSecretB, KEX_BYTES, T, temp, MSG_BYTES + MSG_BYTES);  //H3(keya,keyb);

	return 0;
}

int kex_send_b(unsigned char * pka, unsigned long long pka_byts, unsigned char * ma, unsigned long long ma_byts, unsigned char * pb, unsigned long long * pb_byts, unsigned char * mb, unsigned long long * mb_byts, unsigned char * ss, unsigned long long * ss_byts)
{
	unsigned char ciphertextA1[596] = { 0 };
	unsigned char ePublicKeyA0[564] = { 0 };
	unsigned char ssKeyB[48] = { 0 };
	unsigned char tempm[64] = { 0 };

	memcpy(ssKeyB, pb, 48);
	rand_byts(64, tempm);

	memcpy(ciphertextA1, ma, CRYPTO_CIPHERTEXTBYTES);
	memcpy(ePublicKeyA0, ma + CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES);
	KEX_kdfB(ss, tempm, mb, ssKeyB, pka, ePublicKeyA0, ciphertextA1);

	*pb_byts = 48;
	*mb_byts = 628;
	*ss_byts = 32;
	return 0;
}




int KEX_kdfA(unsigned char* SharedSecretA, const unsigned char* sPrivateKeyA, const unsigned char* ciphertextB, unsigned char* ePrivateKeyA2, unsigned char* KeyA1)
{
	unsigned char temp[MSG_BYTES * 2] = { 0 };
	unsigned char KeyB[MSG_BYTES] = { 0 };
	const uint16_t T = 4;
	ckem_dec(KeyB, ciphertextB, sPrivateKeyA, ePrivateKeyA2);

	memcpy(&temp[0], KeyB, MSG_BYTES);
	memcpy(&temp[MSG_BYTES], KeyA1, MSG_BYTES);
	cshake256_simple(SharedSecretA, KEX_BYTES, T, temp, MSG_BYTES + MSG_BYTES);

	return 0;
}


int kex_resp_a(unsigned char * mb, unsigned long long mb_byts, unsigned char * pa, unsigned long long * pa_byts, unsigned char * ma, unsigned long long * ma_byts, unsigned char * ss, unsigned long long * ss_byts)
{
	unsigned char ePrivateKeyA2[47] = { 0 };
	unsigned char ssKeyA[47] = { 0 };
	unsigned char KeyA1[32] = { 0 };

	memcpy(ssKeyA, pa, 47);
	memcpy(ePrivateKeyA2, pa+47, 47);
	memcpy(KeyA1, pa + 94, 32);

	KEX_kdfA(ss, ssKeyA, mb, ePrivateKeyA2, KeyA1);
	
	*pa_byts = 126;
	*ma_byts = 0;
	*ss_byts = 32;

	return 0;

}
