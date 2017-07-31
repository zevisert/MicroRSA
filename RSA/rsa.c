/* 
SENG 440 
RSA Cryptography
 
Copyright (C) 2017 Zev Isert
*/

#include <stdio.h>
#include <stdlib.h>

//#define VERBOSE

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
const uint_64 prime1 = 61;

/* calculate the second prime (Q) */
const uint_64 prime2 = 53;

/* calculate the modulus (M = P*Q) */
const uint_64 modulus = 3233;

/* choose the public exponent (E) */
const uint_64 publ_exponent = 17;

/* choose the private exponent (D) */
const uint_64 priv_exponent = 2753;


uint_64 encrypt(uint_64 payload, key publkey);
uint_64 decrypt(uint_64 payload, key privkey);

uint_8 bitlen(uint_64 x);
uint_64 mmm(uint_64 X, uint_64 Y, uint_64 M);
uint_64 mmms(uint_64 X, uint_64 Y, uint_64 M);
uint_64 exp(uint_64 X, uint_64 E, uint_64 M);
uint_64 mme(uint_64 X, uint_64 E, uint_64 M);


#define BITAT(X, i) ((X & i) != 0ULL)
#define MAX3(X, Y, M) X > Y ? X > M ? X : M : Y > M ? Y : M

int main(int argc, char** argv)
{ 
	uint_64 input = 123;
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
	printf("17 * 22 * (sf: 18) %% 23 = %llu \nExpected 16 (mmm)\n\n", output);

	if (argc == 4)
	{
		uint_64 X = strtoull(argv[1], NULL, 10);
		uint_64 Y = strtoull(argv[2], NULL, 10);
		uint_64 M = strtoull(argv[3], NULL, 10);

		printf("mme(X: %llu, Y: %llu, M: %llu) => %llu\n", X, Y, M, mme(X, Y, M));
	}

	#ifdef VERBOSE
	printf("On this platform we have:\n"
		   "%2i bits: unsigned long long int\n"
		   "%2i bits: unsigned long int\n"
		   "%2i bits: unsigned int\n"
		   "%2i bits: unsigned short int\n"
		   "%2i bits: unsigned char (byte)\n",
		   bitlen(llui), bitlen(lui), bitlen(ui), bitlen(sui), bitlen(byte)
	);
	#endif

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

uint_64 exp(uint_64 X, uint_64 E, uint_64 M)
{
	uint_64 c = 1;
	uint_64 e = 1;

	for (; e <= E; e += 1)
	{
		c = (X * c) % M;
	}

	return c;
}

uint_64 mme(uint_64 X, uint_64 E, uint_64 M)
{
	uint_8 e = bitlen(E);
	uint_8 m = bitlen(MAX3(X, E, M));
	uint_64 R = 1 << m;
	uint_64 RR = (R << m) % M;

	// Z = 1, P = X
	// Scale Z and P by R^2
	uint_64 Z = mmm(1, RR, M);
	uint_64 P = mmm(X, RR, M);

	register unsigned int i = 0;

	// For i = 0 to n-1 
	for (; i < e; i += 1)
	{
		// If E_i == 1 then Z_i+1 = Z_i * P_i mod M 
		if ((E >> i) & 0x1)
		{
			Z = mmm(Z, P, M);
		}
		else
		{
			// Else Z_i+1 = Z_i
			// nop;
		}

		// P_i+1 = P_i*P_i mod M
		P = mmm(P, P, M);

	}

	//Descale
	return mmm(1, Z, M);
}

uint_64 mmms(uint_64 X, uint_64 Y, uint_64 M)
{
	uint_8 m = bitlen(MAX3(X, Y, M));
	uint_64 RR = (1 << (2 * m)) % M;

	uint_64 XR = mmm(X, RR, M);
	uint_64 YR = mmm(Y, RR, M);
	uint_64 ZR = mmm(XR, YR, M);
	uint_64 Z  = mmm(ZR, 1, M);
	printf("mmms chain:\n"
		"\t XR mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n"
		"\t YR mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n"
		"\t ZR mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n"
		"\t Z  mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n\n",
		X, RR, M, XR,
		Y, RR, M, YR,
		XR, YR, M, ZR,
		ZR, 1ULL, M, Z);
	return Z;
}

uint_64 mmm(uint_64 X, uint_64 Y, uint_64 M)
{
	uint_8 m = bitlen(MAX3(X, Y, M));
	uint_64 R = 1 << m;

	uint_64 T = 0;
	register uint_64 i = 1 << 0;
	register uint_64 nu;

	#ifdef VERBOSE
	unsigned register int j = 0;
	#endif

	for (; i < R; i <<= 1)
	{
		/* nu = T(0) OR (X(i) AND Y(0)) where B(n) is the nth bit of B from the right */
		nu = BITAT(T, 1 << 0) | (BITAT(X, i) & BITAT(Y, 1 << 0));
	
		/* T = ( T + X(i) * Y + nu * M ) / 2 */
		T = (T + BITAT(X, i) * Y + nu * M) >> 1;

		#ifdef VERBOSE
		j += 1;
		printf("i: %03llu, X(%2d): %d, nu: %llu, T: %llu\n", i, j, BITAT(X, i), nu, T);
		#endif // VERBOSE

	}
	
	if (T >= M)
	{
		T -= M;
	}

	return T;
}