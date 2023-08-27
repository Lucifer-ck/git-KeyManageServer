#ifndef _SecretKeyInfo_H_
#define _SecretKeyInfo_H_
/*RSA��Կ*/
// RSA2048
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st   // RSA2048��Կ�ṹ
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st   // RSA2048˽Կ�ṹ
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

/*ECC��Կ*/
#define ECCref_MAX_BITS					512 
#define ECCref_MAX_LEN					((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN			136

typedef struct ECCrefPublicKey_st   // ECC��Կ�ṹ
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st   // ECC˽Կ�ṹ
{
	unsigned int  bits;
	unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*ECC ����*/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int  L;
	unsigned char C[1];
} ECCCipher;

/*ECC ǩ��*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;
#endif // _SecretKeyInfo_H_
