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

void funcs(char* func_name, uint_64 X, uint_64 Y, uint_64 M)
{
	if (strcmp(func_name, "-mmm") == 0)
	{
		uint_64 R_inv = mmm(1, 1, M);
		printf("mmm(X: %llu, Y: %llu, M: %llu) => %llu * %llu * (sf: %llu) %% %llu => %llu\n", X, Y, M, X, Y, R_inv, M, mmm(X, Y, M));
	}
	else if (strcmp(func_name, "-mod") == 0)
	{
		printf("mod(X: %llu, E: %llu, M: %llu) => %llu * %llu %% %llu => %llu\n", X, Y, M, X, Y, M, X * Y % M);
	}
	else if (strcmp(func_name, "-mmms") == 0)
	{
		printf("mmms(X: %llu, Y: %llu, M: %llu) => %llu * %llu %% %llu => %llu\n", X, Y, M, X, Y, M, mmms(X, Y, M));
	}
	else if (strcmp(func_name, "-mme") == 0)
	{
		printf("mme(X: %llu, E: %llu, M: %llu) => %llu ^ %llu %% %llu => %llu\n", X, Y, M, X, Y, M, mme(X, Y, M));
	}
	else if (strcmp(func_name, "-exp") == 0)
	{
		printf("exp(X: %llu, E: %llu, M: %llu) => %llu ^ %llu %% %llu => %llu\n", X, Y, M, X, Y, M, exp(X, Y, M));
	}
}

void test_platform()
{
	printf("On this platform we have:\n"
	   "%2i bits: unsigned long long int\n"
	   "%2i bits: unsigned long int\n"
	   "%2i bits: unsigned int\n"
	   "%2i bits: unsigned short int\n"
	   "%2i bits: unsigned char (byte)\n",
		bitlen((uint_64)-1),
		bitlen((uint_32)-1),
		bitlen((unsigned int)-1),
		bitlen((uint_16)-1),
		bitlen((uint_8)-1));
}

void test_bitlen(void)
{
	printf("---------------- bitlen tests ----------------\n");
	printf(" > bitlen(0)                    => %4hu [expected 0]\n", bitlen(0));
	printf(" > bitlen(1)                    => %4hu [expected 1]\n", bitlen(1));
	printf(" > bitlen(-1)                   => %4hu [expected 64]\n", bitlen(-1));
	printf(" > bitlen(0xFFFF)               => %4hu [expected 16]\n", bitlen(0xFFFF));
	printf(" > bitlen(0x0x2222222222222222) => %4hu [expected 62]\n", bitlen(0x2222222222222222));
}

void test_mmm(void)
{
	printf("----------------- mmm tests ------------------\n");
	printf(" > mmm(0, 0, 0)                 => %4llu [expected 0]\n", mmm(0, 0, 0));
	printf(" > mmm(1, 1, 1)                 => %4llu [expected 0]\n", mmm(1, 1, 1));
	printf(" > mmm(1, 1, 500)               => %4llu [expected 192]\n", mmm(1, 1, 500));
	printf(" > mmm(17, 22, 23)              => %4llu [expected 16]\n", mmm(17, 22, 23));
	printf(" > mmm(855, 855, 3233)          => %4llu [expected 2413]\n", mmm(855, 855, 3233));
}

void test_mmms(void)
{
	printf("----------------- mmms tests -----------------\n");
	printf(" > mmms(0, 0, 1)                => %4llu [expected 0]\n", mmms(0, 0, 1));
	printf(" > mmms(1, 1, 1)                => %4llu [expected 1]\n", mmms(1, 1, 1));
	printf(" > mmms(1, 1, 500)              => %4llu [expected 1]\n", mmms(1, 1, 500));
	printf(" > mmms(17, 22, 23)             => %4llu [expected 6]\n", mmms(17, 22, 23));
	printf(" > mmms(855, 855, 3233)         => %4llu [expected 367]\n", mmms(855, 855, 3233));
}

void test_mme(void)
{
	printf("----------------- mme tests ------------------\n");
	printf(" > mme(0, 1, 1)                 => %4llu [expected 0]\n", mme(0, 1, 1));
	printf(" > mme(1, 1, 1)                 => %4llu [expected 0]\n", mme(1, 1, 1));
	printf(" > mme(1, 1, 500)               => %4llu [expected 1]\n", mme(1, 1, 500));
	printf(" > mme(51, 43, 427)             => %4llu [expected 275]\n", mme(51, 43, 427));
	printf(" > mme(855, 2, 3233)            => %4llu [expected 367]\n", mme(855, 2, 3233));
	printf(" > mme(123, 17, 3233)           => %4llu [expected 855]\n", mme(123, 17, 3233));
	printf(" > mme(855, 2753, 3233)         => %4llu [expected 123]\n", mme(855, 2753, 3233));
}

void run_tests(void)
{
	test_platform();
	test_bitlen();
	test_mmm();
	test_mmms();
	test_mme();
}

int main(int argc, char** argv)
{ 
	uint_64 input = 123;
	key publkey = { publ_exponent, modulus };
	key privkey = { priv_exponent, modulus };
	
	if (argc == 5)
	{
		uint_64 X = strtoull(argv[2], NULL, 10);
		uint_64 Y = strtoull(argv[3], NULL, 10);
		uint_64 M = strtoull(argv[4], NULL, 10);

		funcs(argv[1], X, Y, M);
	}
	else
	{
		run_tests();
	}

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

	#ifdef VERBOSE
	printf("mmms chain:\n"
		"\t XR mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n"
		"\t YR mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n"
		"\t ZR mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n"
		"\t Z  mmm(X: %3llu, Y: %3llu, M: %3llu) => %3llu\n\n",
		X, RR, M, XR,
		Y, RR, M, YR,
		XR, YR, M, ZR,
		ZR, 1ULL, M, Z);
	#endif

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
