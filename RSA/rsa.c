/* 
SENG 440 
RSA Cryptography
 
Copyright (C) 2017 Zev Isert
*/ 
 
#include <stdio.h>
#include <stdlib.h>

// #define VERBOSE

typedef unsigned long long int uint_64;
typedef unsigned long int uint_32;
typedef unsigned short int uint_16;
typedef unsigned char uint_8;
typedef struct
{
	const uint_64 exponent;
	const uint_64 modulus;
} key;


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


uint_64 encrypt(uint_64 payload, key publkey);
uint_64 decrypt(uint_64 payload, key privkey);

uint_8 bitlen(uint_64 x);
uint_64 mmm(uint_64 X, uint_64 Y, uint_64 M);
uint_64 mme(uint_64 X, uint_64 E, uint_64 M);

#define BITAT(X, i) ((X & i) != 0)

int main(void)
{ 
	int input = 123;
	key publkey = { publ_exponent, modulus };
	key privkey = { priv_exponent, modulus };
	
	uint_64 llui = -1;
	uint_32 lui = -1;
	unsigned int ui = -1;
	uint_16 sui = -1;
	uint_8 byte = -1;

	uint_64 output = mme(4, 13, 497);
	printf("4^13 %% 497 = %llu\nExpected 445 (mme)\n\n", output);

	output = mmm(17, 22, 23);
	printf("17 * 22 * (sf: -5) %% 23 = %llu \nExpected 16 (mmm)\n\n", output);

	printf("On this platform we have:\n"
		   "%2i bits: unsigned long long int\n"
		   "%2i bits: unsigned long int\n"
		   "%2i bits: unsigned int\n"
		   "%2i bits: unsigned short int\n"
		   "%2i bits: unsigned char (byte)\n",
		   bitlen(llui), bitlen(lui), bitlen(ui), bitlen(sui), bitlen(byte)
	);

	exit(0);
} 

uint_64 encrypt(uint_64 payload, key publkey)
{
	/* output = payload ^ publkey % modulus */
	return mme(payload, publkey.exponent, publkey.modulus);
}

uint_64 decrypt(uint_64 payload, key privkey)
{
	/* output = payload ^ privkey % modulus */
	return mme(payload, privkey.exponent, privkey.modulus);
}

uint_8 bitlen(uint_64 x)
{
	uint_8 bits = 0;
	uint_64 val = x;
	for (; val != 0; ++bits) val >>= 1;
	return bits;
}

uint_64 mme(uint_64 X, uint_64 E, uint_64 M)
{
	uint_64 c = 1;
	uint_64 e = 1;

	for (; e <= E; e += 1)
	{
		//c = mmm(X, c, M);
		c = (X * c) % M;
	
		#ifdef VERBOSE
		printf("e = %i | c = %i\n", e, c);
		#endif //VERBOSE
	}

	return c;
}


uint_64 mmm(uint_64 X, uint_64 Y, uint_64 M)
{
	uint_8 m = bitlen(M);
	uint_64 R = 1 << m;

	uint_64 T = 0;
	register uint_64 i = 1;
	register uint_64 nu;

	#ifdef VERBOSE
	unsigned register int j = 0;
	#endif // VERBOSE

	for (; i < R; i <<= 1)
	{
		/* nu = T(0) OR (X(i) AND Y(0)) where B(n) is the nth bit of B from the right */
		nu = BITAT(T, 0x1) | (BITAT(X, i) & BITAT(Y, 0x1));
	
		/* T = ( T + X(i) * Y + nu * M ) / 2 */
		T = (T + BITAT(X, i) * Y + nu * M) >> 1;

		#ifdef VERBOSE
		j += 1;
		printf("i: %d, X(i): %d, nu: %d, T: %d\n", j, BITAT(X, i), nu, T);			  
		#endif // VERBOSE

	}
	
	if (T >= M)
	{
		T -= M;
	}

	return T;
}