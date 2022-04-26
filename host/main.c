/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	int cipherkey=0;
	char tmp[2] = {0,};

	char RSA_plaintext[MAX_PLAIN_LEN_1024] = {0,};
	char RSA_ciphertext[RSA_CIPHER_LEN_1024] = {0,};

	FILE* fp;
	FILE* fp_text;
	FILE* fp_key;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	if (strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "Ceaser") == 0){
			
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		op.params[1].value.a = 0;

		
		printf("1. Read the file\n");
		fp = fopen(argv[2], "r");
		fread(plaintext, sizeof(plaintext), 1, fp);
		fclose(fp);
		
		printf("Plaintext : %s\n", plaintext);

		printf("2. Generate Random Key\n");
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_GENERATE_RANDOMKEY,
						 &op, &err_origin);

		printf("3. Encryption\n");
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		cipherkey = op.params[1].value.a;

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", ciphertext);
		printf("Cipherkey : %d\n", cipherkey);

		printf("4. Save File\n");

		fp_text = fopen("enc_text.txt", "wb");
		if (fp_text == NULL)
		{
			fprintf(stderr, "File Open Error!\n");
			exit(1);
		}
		fwrite(ciphertext, strlen(ciphertext), 1, fp_text);
		fclose(fp_text);
		printf("File name : %s\n", "enc_text.txt");

		sprintf(tmp, "%d", cipherkey);
		fp_key = fopen("enc_key.txt", "wb");
		fwrite(tmp, strlen(tmp), 1, fp_key);		
		fclose(fp_key);
		printf("File name : %s\n", "enc_key.txt");
		
	}
	else if (strcmp(argv[1], "-d") == 0){

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		op.params[1].value.a = 0;

		printf("1. Read the file\n");
		fp_text = fopen(argv[2], "r");
		fread(ciphertext, sizeof(ciphertext), 1, fp_text);
		fclose(fp_text);

		fp_key = fopen(argv[3], "r");
		fread(tmp, sizeof(tmp), 1, fp_key);
		fclose(fp_key);
		
		printf("2. Decryption\n");
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		
		cipherkey = atoi(tmp);
		op.params[1].value.a = cipherkey;

		printf("Ciphertext : %s\n", ciphertext);
		printf("Cipherkey : %d\n", cipherkey);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);

		printf("3. Save File\n");
		fp_text = fopen("dec.txt", "wb");
		fwrite(plaintext, strlen(plaintext), 1, fp_text);
		fclose(fp_text);
		printf("File name : %s\n", "dec.txt");
		
	}
	else if(strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "RSA") == 0){
		char *rsa_cipher = NULL;
		
		printf("Start RSA encryption\n");
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		
		op.params[0].tmpref.buffer = RSA_plaintext;
		op.params[0].tmpref.size = MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = RSA_ciphertext;
		op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

		printf("1. Read the file\n");
		fp = fopen(argv[2], "r");
		fread(plaintext, sizeof(plaintext), 1, fp);
		fclose(fp);
		
		printf("Plaintext : %s\n", plaintext);

		printf("2. Create RSA Key Pair\n");

		res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_CREATE_KEY_PAIR, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		printf("3. Encryption\n");

		res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		rsa_cipher = RSA_ciphertext;
		printf("Ciphertext : %s\n", rsa_cipher);

		printf("4. Save File\n");
		fp_text = fopen("RSA_text.txt", "wb");
		if (fp_text == NULL)
		{
			fprintf(stderr, "File Open Error!\n");
			exit(1);
		}
		fwrite(rsa_cipher, strlen(rsa_cipher), 1, fp_text);
		fclose(fp_text);
		printf("File name : %s\n", "RSA_text.txt");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
