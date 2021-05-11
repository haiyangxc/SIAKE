/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism
*********************************************************************************************/ 


// Benchmark and test parameters  
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) 
    #define BENCH_LOOPS        10      // Number of iterations per bench 
    #define TEST_LOOPS         1      // Number of iterations per test
#else
    #define BENCH_LOOPS       10
    #define TEST_LOOPS        1      
#endif



int cryptotest_SIAKE()
{// Testing SIAKE
    unsigned int i;
    unsigned char skA[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char skA0[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pkA[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char pkA0[CRYPTO_PUBLICKEYBYTES] = {0};
	unsigned char ctA[CRYPTO_CIPHERTEXTBYTES + 32] = {0};
    unsigned char ssA[CRYPTO_BYTES] = {0};
    unsigned char ssA_[CRYPTO_BYTES] = {0};
	unsigned char tempA[2*CRYPTO_BYTES] = {0};

	unsigned char skB[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pkB[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ctB[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ssB[CRYPTO_BYTES] = {0};
    unsigned char ssB_[CRYPTO_BYTES] = {0};
	unsigned char tempB[2*CRYPTO_BYTES] = {0};
	
	// session key
	unsigned char sskeyA[CRYPTO_BYTES] = {0};
	unsigned char sskeyB[CRYPTO_BYTES] = {0};
    
	
	
	bool passed = true;
	
	/**********Regist  Phase**************/
	
	//Regist public and secret key for Alice
	crypto_2kem_keypairA(pkA, skA);
	
	//Regist public and secret key for Bob
	crypto_kem_keypair(pkB, skB);
	
	
	/************AKE Exe Phase**********/
	/*   Alice sends the first message    */
	crypto_2kem_keypairA(pkA0, skA0);
	crypto_kem_enc(ctB, ssB, pkB);
	
	/*   Bob sends the first message    */
	crypto_2kem_enc(ctA, ssA, pkA, pkA0);
	
	/*   Bob extracts the session key */
	crypto_kem_dec(ssB_, ctB, skB);
	memcpy(&tempB[0], ssA, CRYPTO_BYTES);
	memcpy(&tempB[CRYPTO_BYTES], ssB_, CRYPTO_BYTES);
	shake256(sskeyB, CRYPTO_BYTES, tempB, 2*CRYPTO_BYTES);
	/*   Alice extracts the session key*/
	crypto_2kem_dec(ssA_, ctA, skA, skA0);
	memcpy(&tempA[0], ssA_, CRYPTO_BYTES);
	memcpy(&tempA[CRYPTO_BYTES], ssB, CRYPTO_BYTES);
	shake256(sskeyA, CRYPTO_BYTES, tempA, 2*CRYPTO_BYTES);
	
	 if (memcmp(sskeyA, sskeyB, CRYPTO_BYTES) != 0) {
            passed = false;
	 }
	 
	 if (passed == true) printf("SIAKE tests .................................................... PASSED");
    else { printf("SIAKE tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n"); 
	
	return PASSED;
}


int cryptorun_SIAKE()
{// Testing SIAKE
    unsigned int n;
    unsigned char skA[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char skA0[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pkA[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char pkA0[CRYPTO_PUBLICKEYBYTES] = {0};
	unsigned char ctA[CRYPTO_CIPHERTEXTBYTES + 32] = {0};
    unsigned char ssA[CRYPTO_BYTES] = {0};
    unsigned char ssA_[CRYPTO_BYTES] = {0};
	unsigned char tempA[2*CRYPTO_BYTES] = {0};

	unsigned char skB[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pkB[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ctB[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ssB[CRYPTO_BYTES] = {0};
    unsigned char ssB_[CRYPTO_BYTES] = {0};
	unsigned char tempB[2*CRYPTO_BYTES] = {0};
	
	// session key
	unsigned char sskeyA[CRYPTO_BYTES] = {0};
	unsigned char sskeyB[CRYPTO_BYTES] = {0};
    
    unsigned long long cycles_resist = 0, cycles_Alicefirst = 0, cycles_Aliceextract = 0, cycles_Bob = 0, cycles1, cycles2;

    printf("\n\nBENCHMARKING SIAKE %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (n = 0; n < BENCH_LOOPS; n++)
    {
	
	
	// Benchmarking Regist  Phase
	cycles1 = cpucycles();
	crypto_2kem_keypairA(pkA, skA);
	crypto_kem_keypair(pkB, skB);
	cycles2 = cpucycles();
	cycles_resist = cycles_resist + (cycles2-cycles1);
	
	
	// Benchmarking  Alice sends the first message 
	cycles1 = cpucycles();
	
	crypto_2kem_keypairA(pkA0, skA0);
	crypto_kem_enc(ctB, ssB, pkB);
	
	cycles2 = cpucycles();
	cycles_Alicefirst = cycles_Alicefirst + (cycles2-cycles1);
	
	// Benchmarking Bob sends the first message and extract key
	
	cycles1 = cpucycles();
	crypto_2kem_enc(ctA, ssA, pkA, pkA0);
	crypto_kem_dec(ssB_, ctB, skB);
	memcpy(&tempB[0], ssA, CRYPTO_BYTES);
	memcpy(&tempB[CRYPTO_BYTES], ssB_, CRYPTO_BYTES);
	shake256(sskeyB, CRYPTO_BYTES, tempB, 2*CRYPTO_BYTES);
	
	cycles2 = cpucycles();
	cycles_Bob = cycles_Bob + (cycles2-cycles1);
	
	
	
	// Benchmarking  Alice extracts the session key
	cycles1 = cpucycles();
		
	crypto_2kem_dec(ssA_, ctA, skA, skA0);
	memcpy(&tempA[0], ssA_, CRYPTO_BYTES);
	memcpy(&tempA[CRYPTO_BYTES], ssB, CRYPTO_BYTES);
	shake256(sskeyA, CRYPTO_BYTES, tempA, 2*CRYPTO_BYTES);
	
	cycles2 = cpucycles();
	cycles_Aliceextract = cycles_Aliceextract + (cycles2-cycles1);
	
	}
	
    printf("  Key Registration runs in ....................................... %10lld ", cycles_resist/BENCH_LOOPS); print_unit;
    printf("\n");
    printf("  Alice's first message runs in ........................................ %10lld ", cycles_Alicefirst/BENCH_LOOPS); print_unit;
    printf("\n");        
    printf("  Bob runs in ........................................ %10lld ", cycles_Bob/BENCH_LOOPS); print_unit;
	printf("\n");
	printf("  Alice's extraction runs in ........................................ %10lld ", cycles_Aliceextract/BENCH_LOOPS); print_unit;
    printf("\n");  
    

    return PASSED;	
	

}



int main()
{
    int Status = PASSED;
    
   Status = cryptotest_SIAKE();             // Test key encapsulation mechanism
    if (Status != PASSED) {
        printf("\n\n   Error detected: SIAKE_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }
	
   Status = cryptorun_SIAKE();              // Benchmark key encapsulation mechanism
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }

    return Status;
}