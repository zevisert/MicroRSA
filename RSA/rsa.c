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

unsigned int bitlen(unsigned long long int x);
unsigned int mmm(unsigned int X, unsigned int Y, unsigned int M);

#define BITTST(X, i) ((X & i) != 0)

int main(void)
{ 
	int input = 123;
	key publkey = { publ_exponent, modulus };
	key privkey = { priv_exponent, modulus };
	int output = mmm(17, 22, 23);
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

unsigned int bitlen(unsigned long long int x)
{
	unsigned int bits = 0;
	unsigned long long int val = x;
	for (; val != 0; ++bits) val >>= 1;
	return bits;
}

unsigned int mmm(unsigned int X, unsigned int Y, unsigned int M)
{
	unsigned int m = bitlen(M);
	unsigned int R = 1 << m;

	unsigned int T = 0;
	unsigned register int i = 1;
	unsigned register int nu;

	#ifdef VERBOSE
	unsigned register int j = 0;
	#endif // VERBOSE

	for (; i < R; i <<= 1)
	{
		/* nu = T(0) OR (X(i) AND Y(0)) where B(n) is the nth bit of B from the right */
		nu = BITTST(T, 0x1) | (BITTST(X, i) & BITTST(Y, 0x1));
	
		/* T = ( T + X(i) * Y + nu * M ) / 2 */
		T = (T + BITTST(X, i) * Y + nu * M) >> 1;

		#ifdef VERBOSE
		j += 1;
		printf("i: %d, X(i): %d, nu: %d, T: %d\n", j, BITTST(X, i), nu, T);			  
		#endif // VERBOSE

	}
	
	if (T >= M)
	{
		T -= M;
	}

	return T;
}