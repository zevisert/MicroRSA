/* 
SENG 440 
RSA Cryptography
 
Copyright (C) 2017 Zev Isert
*/ 
 
#include <stdio.h>
#include <stdlib.h>



/* calculate the first prime (P) */
const unsigned int prime1 = 61;

/* calculate the second prime (Q) */
const unsigned int prime2 = 53;

/* calculate the modulus (M = P*Q) */
const unsigned int modulus = 3233;

/* choose the public exponent (E) */
const unsigned int publ_exponent = 17;

/* choose the private exponent (D) */
const unsigned int priv_exponent = 2753;

typedef struct
{
	const unsigned int exponent;
	const unsigned int modulus;
} key;


int encrypt(int payload, key publkey);
int decrypt(int payload, key privkey);


int main(void)
{ 
	int input = 123;
	key publkey = { publ_exponent, modulus };
	key privkey = { priv_exponent, modulus };
	int output = encrypt(input, publkey);
	printf("%d\n", output);
	output = decrypt(output, privkey);
	printf("%d\n", output);
	exit(0);
} 

int encrypt(int payload, key publkey)
{
	/* output = payload ^ publkey % modulus */
	long long unsigned int out = payload;
	register int i = 0;
	for (; i < publkey.exponent; i += 1)
	{
		out *= payload;
	}
	return out % publkey.modulus;
}

int decrypt(int payload, key privkey)
{
	/* output = payload ^ privkey % modulus */
	long long unsigned int out = payload;
	register int i = 0;
	for (; i < privkey.exponent; i += 1)
	{
		out *= payload;
	}
	return out % privkey.modulus;
}