/********************************************************************************************
* Modified from SIDH: an efficient supersingular isogeny cryptography library
* By 薛海洋，徐秀
* Abstract: benchmarking/testing SIAKE
*********************************************************************************************/



// Benchmark and test parameters  
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) || (TARGET == TARGET_ARM64) 
#define BENCH_LOOPS        100      // 100次运行时间测试
#define TEST_LOOPS         3     // Number of iterations per test
#else
#define BENCH_LOOPS       100  //100次运行时间测试
#define TEST_LOOPS        10   //正确性验证    
#endif

uint32_t cpu_to_be32(uint32_t x)
{
	return (x << 24) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) | ((x >> 24) & 0xff);
}

//正确性验证
int cryptotest_AKE()
{ // Testing AKE

	unsigned char sPrivateKeyA[KEX_s_A_SECRETKEYBYTES] = { 0 }, sPublicKeyA[CRYPTO_PUBLICKEYBYTES] = { 0 };//Static secret\public key for initator A
	unsigned char  sPrivateKeyB[KEX_s_B_SECRETKEYBYTES] = { 0 }, sPublicKeyB[CRYPTO_PUBLICKEYBYTES] = { 0 };//Static secret\public key for responder B
	unsigned long long pka_byts = 564, ska_byts = 47, pkb_byts = 564, skb_byts = 48;

	unsigned char  pa[126] = { 0 }, pb[48] = { 0 };
	unsigned long long pa_byts = 254, pb_byts = 160;

	unsigned char       entropy_input[48];
	unsigned int i, j;
	bool passed = true;

	unsigned long long ma_byts = 1160;
	unsigned char ma[2 * CRYPTO_PUBLICKEYBYTES + MSG_BYTES] = { 0 };

	unsigned long long mb_byts = 628, ss_byts = 32;
	unsigned char mb[CRYPTO_PUBLICKEYBYTES + MSG_BYTES * 2] = { 0 };
	/*   Final SessionKey parameters    */
	unsigned char  SharedSecretA[KEX_BYTES] = { 0 }, SharedSecretB[KEX_BYTES] = { 0 };//Session Keys

	FILE *fp2;
	uint32_t len[1];

	printf("\n\nTESTING ISOGENY-BASED AKE %s\n", SCHEME_NAME);
	printf("--------------------------------------------------------------------------------------------------------\n\n");

	
	//create kat file
	printf("\ntest data of kex is generated in KEX_VEC_INFO.dat\n");
	fp2 = fopen("KEX_VEC_INFO.dat", "wb");
	if (fp2 == NULL)
	{
		return -1;
	}
	
	for (int i = 0; i < 48; i++)
		entropy_input[i] = i;
	rand_init(entropy_input, 48);
	len[0] = cpu_to_be32(48);
	fwrite(len, sizeof(uint32_t), 1, fp2);
	//fprintf(fp, "\nSEED\n");
	fwrite(entropy_input, sizeof(unsigned char), 48, fp2);
	
	for (j = 0; j < TEST_LOOPS; j++)
	{
		
		kex_init_a(sPublicKeyA, &pka_byts, sPrivateKeyA, &ska_byts, pa, &pa_byts);
		kex_init_b(sPublicKeyB, &pkb_byts, sPrivateKeyB, &skb_byts, pb, &pb_byts);

		//fprintf(fp, "\nAlice_SK_LEN\n");
		len[0] = cpu_to_be32(ska_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nSKA\n");
		fwrite(sPrivateKeyA, sizeof(unsigned char), ska_byts, fp2);


		//fprintf(fp, "\nAlice_PK_LEN\n");
		len[0] = cpu_to_be32(pka_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nPKA\n");
		fwrite(sPublicKeyA, sizeof(unsigned char), pka_byts, fp2);


		//fprintf(fp, "\nBob_SK_LEN\n");
		len[0] = cpu_to_be32(skb_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nSKB\n");
		fwrite(sPrivateKeyB, sizeof(unsigned char), skb_byts, fp2);


		//fprintf(fp, "\nBob_PK_LEN\n");
		len[0] = cpu_to_be32(pkb_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nPKB\n");
		fwrite(sPublicKeyB, sizeof(unsigned char), pkb_byts, fp2);


		//fprintf(fp, "\nkex_init_a pa_len\n");
		len[0] = cpu_to_be32(pa_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\npa\n");
		fwrite(pa, sizeof(unsigned char), pa_byts, fp2);

		//fprintf(fp, "\nkex_init_b pb_len\n");
		len[0] = cpu_to_be32(pb_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\npb\n");
		fwrite(pb, sizeof(unsigned char), pb_byts, fp2);




		/************AKE Exe Phase**********/
		

		/*As a initiator A generates ephemeral public key ePublicKeyA0, *
		*ciphertext ciphertextA1 under B's public key sPublicKeyB*      *
		*and send-----ciphertextA1, ePublicKeyA0----------> to B        *
		* A keeps sPrivateKeyA, KeyA1 for next round*
		**/
		kex_send_a(sPublicKeyB, pkb_byts, pa, &pa_byts, ma, &ma_byts);


		//fprintf(fp, "\nkex_send_a pa_len\n");
		len[0] = cpu_to_be32(pa_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nkex_send_a pa\n");
		fwrite(pa, sizeof(unsigned char), pa_byts, fp2);

		//fprintf(fp, "\nkex_send_a ma_len\n");
		len[0] = cpu_to_be32(ma_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nkex_send_a ma\n");
		fwrite(ma, sizeof(unsigned char), ma_byts, fp2);



		/*On receiving ePublicKeyA0, ciphertextA1 form A, the responder B  *
		*decapsulated KeyA_ coresponding to ciphertextA1, computes ciphertext  *
		*under public keys sPublicKeyA and ePublicKeyA0, and the corresponding KeyB *
		*       A <------ciphertextB------------- B
		* Generates the final session key SharedSecretB*
		**/
		kex_send_b(sPublicKeyA, pka_byts, ma, ma_byts, pb, &pb_byts, mb, &mb_byts, SharedSecretB, &ss_byts);
		/*On receiving ciphertextB from B, *
		*User A decapsulated KeyB_ coresponding to ciphertextB,  *
		*  computes the final session key SharedSecretA*
		**/
		//fprintf(fp, "\nkex_send_b pb_len\n");
		len[0] = cpu_to_be32(pb_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\npb\n");
		fwrite(pb, sizeof(unsigned char), pb_byts, fp2);

		//fprintf(fp, "\nkex_send_b mb_len\n");
		len[0] = cpu_to_be32(mb_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nkex_send_b mb\n");
		fwrite(mb, sizeof(unsigned char), mb_byts, fp2);

		//KEX_kdfA(SharedSecretA, sPrivateKeyA, mb);
		kex_resp_a(mb, mb_byts, pa, &pa_byts, ma, &ma_byts, SharedSecretA, &ss_byts);

		//fprintf(fp, "\nkex_resp_a ma_len\n");
		len[0] = cpu_to_be32(ma_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nkex_send_a ma\n");
		fwrite(ma, sizeof(unsigned char), ma_byts, fp2);


		//fprintf(fp, "\nsession_key_len\n");
		len[0] = cpu_to_be32(ss_byts);
		fwrite(len, sizeof(uint32_t), 1, fp2);
		//fprintf(fp, "\nsession_key\n");
		fwrite(SharedSecretA, sizeof(unsigned char), ss_byts, fp2);

		if (memcmp(SharedSecretA, SharedSecretB, KEX_BYTES) != 0) {//判断SharedSecretA 是否等于SharedSecretB
			passed = false;
			break;
		} 

		

	}

	fclose(fp2);

	if (passed == true) printf("  AKE tests .................................................... PASSED");
	else { printf("  AKE tests ... FAILED"); printf("\n"); return FAILED; }
	printf("\n");

	return PASSED;
}


int hextodec(unsigned char * buff, int len) {
	int num = 0;
	for (int j = 0; j < len; j++) {
		num = num + buff[j] * pow((float)256, len - 1 - j);
	}
	return num;
}

int testake() {

	FILE *fp = NULL;
	unsigned char buff[4];
	unsigned char seed[48];

	unsigned char pka[CRYPTO_PUBLICKEYBYTES], pkb[CRYPTO_PUBLICKEYBYTES], pka_t[CRYPTO_PUBLICKEYBYTES], pkb_t[CRYPTO_PUBLICKEYBYTES];
	unsigned char ska[KEX_s_A_SECRETKEYBYTES], skb[KEX_s_B_SECRETKEYBYTES], pa[126], pb[48];
	unsigned char ska_t[KEX_s_A_SECRETKEYBYTES], skb_t[KEX_s_B_SECRETKEYBYTES], pa_t[126], pb_t[48];
	unsigned char k1[KEX_BYTES], k2[KEX_BYTES], k3[KEX_BYTES], ma[2 * CRYPTO_PUBLICKEYBYTES + MSG_BYTES], mb[CRYPTO_PUBLICKEYBYTES + MSG_BYTES * 2], ma_t[2 * CRYPTO_PUBLICKEYBYTES + MSG_BYTES], mb_t[CRYPTO_PUBLICKEYBYTES + MSG_BYTES * 2];

	
	int i, j;
	unsigned long long pka_byts, ska_byts, pkb_byts, skb_byts, pa_byts, pb_byts, ma_byts, mb_byts, k1_byts, k2_byts;

	unsigned long long label = 0;

	fopen_s(&fp, "KEX_VEC_INFO.dat", "rb");
	int seed_len = 0, sk_len = 0, pk_len = 0, ss_len = 0, pa_len = 0, pb_len = 0, ma_len = 0, mb_len = 0;

	fread(buff, sizeof(unsigned char), 4, fp);
	seed_len = hextodec(buff, 4);
	fread(seed, sizeof(unsigned char), seed_len, fp);
	rand_init(seed, 48);
	
	for (i = 0; i < TEST_LOOPS; i++) {
		kex_init_a(pka, &pka_byts, ska, &ska_byts, pa, &pa_byts);
		kex_init_b(pkb, &pkb_byts, skb, &skb_byts, pb, &pb_byts);
		// for a
		fread(buff, sizeof(unsigned char), 4, fp);
		sk_len = hextodec(buff, 4);
		fread(ska_t, sizeof(unsigned char), sk_len, fp);
		if (memcmp(ska_t, ska, ska_byts) == 0) {
			//printf("\nin send_a pa_t is equal to pa. \n");
		}
		else {
			printf("\nin init_a ska_t is not equal to ska. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		pk_len = hextodec(buff, 4);
		fread(pka_t, sizeof(unsigned char), pk_len, fp);
		if (memcmp(pka_t, pka, pka_byts) == 0) {
			//printf("\nin send_a pa_t is equal to pa. \n");
		}
		else {
			printf("\nin init_a pka_t is not equal to pka. \n");
			label = -1;
		}

		// for b
		fread(buff, sizeof(unsigned char), 4, fp);
		sk_len = hextodec(buff, 4);
		fread(skb_t, sizeof(unsigned char), sk_len, fp);
		if (memcmp(skb_t, skb, skb_byts) == 0) {
			//printf("\nin send_a pa_t is equal to pa. \n");
		}
		else {
			printf("\nin init_b skb_t is not equal to skb. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		pk_len = hextodec(buff, 4);
		fread(pkb_t, sizeof(unsigned char), pk_len, fp);
		if (memcmp(pkb_t, pkb, pkb_byts) == 0) {
			//printf("\nin send_a pa_t is equal to pa. \n");
		}
		else {
			printf("\nin init_b pkb_t is not equal to pkb. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		pa_len = hextodec(buff, 4);
		fread(pa_t, sizeof(unsigned char), pa_len, fp);
		if (memcmp(pa_t, pa, pa_byts) == 0) {
			//printf("\npa_t is equal to pa. \n");
		}
		else {
			printf("\npa_t is not equal to pa. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		pb_len = hextodec(buff, 4);
		fread(pb_t, sizeof(unsigned char), pb_len, fp);
		if (memcmp(pb_t, pb, pb_byts) == 0) {
			//printf("\npb_t is equal to pb. \n");
		}
		else {
			printf("\npb_t is not equal to pb. \n");
			label = -1;
		}

		kex_send_a(pkb_t, pkb_byts, pa, &pa_byts, ma, &ma_byts);
		fread(buff, sizeof(unsigned char), 4, fp);
		pa_len = hextodec(buff, 4);
		fread(pa_t, sizeof(unsigned char), pa_len, fp);
		if (memcmp(pa_t, pa, pa_byts) == 0) {
			//printf("\nin send_a pa_t is equal to pa. \n");
		}
		else {
			printf("\nin send_a pa_t is not equal to pa. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		ma_len = hextodec(buff, 4);
		fread(ma_t, sizeof(unsigned char), ma_len, fp);
		if (memcmp(ma_t, ma, ma_byts) == 0) {
			//printf("\nin send_a ma_t is equal to ma. \n");
		}
		else {
			printf("\nin send_a ma_t is not equal to ma. \n");
			label = -1;
		}

		kex_send_b(pka_t, pka_byts, ma_t, ma_byts, pb_t, &pb_byts, mb, &mb_byts, k1, &k1_byts);
		fread(buff, sizeof(unsigned char), 4, fp);
		pb_len = hextodec(buff, 4);
		fread(pb_t, sizeof(unsigned char), pb_len, fp);
		if (memcmp(pb_t, pb, pb_byts) == 0) {
			//printf("\nin send_b pb_t is equal to pb. \n");
		}
		else {
			printf("\nin send_b pb_t is not equal to pb. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		mb_len = hextodec(buff, 4);
		fread(mb_t, sizeof(unsigned char), mb_len, fp);
		if (memcmp(mb_t, mb, mb_byts) == 0) {
			//printf("\nin send_b mb_t is equal to mb. \n");
		}
		else {
			printf("\nin send_b mb_t is not equal to mb. \n");
			label = -1;
		}

		kex_resp_a(mb_t, mb_byts, pa, &pa_byts, ma, &ma_byts, k2, &k2_byts);

		fread(buff, sizeof(unsigned char), 4, fp);
		ma_len = hextodec(buff, 4);
		fread(ma_t, sizeof(unsigned char), ma_len, fp);
		if (memcmp(ma_t, ma, ma_byts) == 0) {
			//printf("\nin resp_a ma_t is equal to ma. \n");
		}
		else {
			printf("\nin resp_a ma_t is not equal to ma. \n");
			label = -1;
		}

		fread(buff, sizeof(unsigned char), 4, fp);
		ss_len = hextodec(buff, 4);
		fread(k3, sizeof(unsigned char), ss_len, fp);

		if (memcmp(k1, k2, KEX_BYTES) == 0) {
			//printf("\nk1 is equal to k2. \n");
		}
		else {
			printf("\nk1 is not equal to k2. \n");
			label = -1;
		}

		if (memcmp(k3, k2, KEX_BYTES) == 0) {
			//printf("\nk3 is equal to k2. \n");
		}
		else {
			printf("\nk3 is not equal to k2. \n");
			label = -1;
		}
	}


	fclose(fp);
	return label;
}




int main()
{
	


	int Status = PASSED;
	
	Status = cryptotest_AKE();             // Test SIAKE and Gen Data
	if (Status != PASSED) {
		printf("\n\n   Error detected: AKE_ERROR_SHARED_KEY \n\n");
		return FAILED;
	}

	if (testake() == -1) {
		printf("\n\nTest Vector Fail\n\n");
	}
	else printf("\n\nTest Vector Success\n\n");

	system("pause");
	return Status;

}



