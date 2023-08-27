#include "KeyManageImp.h"
#include "servant/Application.h"
#include "SecretKeyInfo.h"

using namespace std;

//////////////////////////////////////////////////////
void KeyManageImp::initialize()
{
	//initialize servant here:
	//...
}

//////////////////////////////////////////////////////
void KeyManageImp::destroy()
{
	//destroy servant here:
	//...
}

// 导出RSA签名公钥
int KeyManageImp::exportSignPublicKey_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("exportSignPublicKey_RSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	pucPublicKey.mLen = 256;
	pucPublicKey.eLen = 256;

	RSArefPublicKey rsaRefPublicKey;

	int errorCode = SDF_ExportSignPublicKey_RSA((void*)singleSessionPtr, uiKeyIndex, &rsaRefPublicKey);


	pucPublicKey.bits = rsaRefPublicKey.bits;
	memcpy(pucPublicKey.m, rsaRefPublicKey.m, pucPublicKey.mLen);
	memcpy(pucPublicKey.e, rsaRefPublicKey.e, pucPublicKey.eLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_ExportSignPublicKey_RSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);

	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.m [param]:" << pucPublicKey.m << endl);
	TLOG_INFO("pucPublicKey.e [param]:" << pucPublicKey.e << endl);

	TLOG_INFO("End of exportSignPublicKey_RSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);
	return errorCode;
}

// 导出RSA加密公钥
int KeyManageImp::exportEncPublicKey_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("exportEncPublicKey_RSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	pucPublicKey.mLen = 256;
	pucPublicKey.eLen = 256;

	RSArefPublicKey rsaRefPublicKey;

	int errorCode = SDF_ExportEncPublicKey_RSA((void*)singleSessionPtr, uiKeyIndex, &rsaRefPublicKey);

	pucPublicKey.bits = rsaRefPublicKey.bits;

	memcpy(pucPublicKey.m, rsaRefPublicKey.m, pucPublicKey.mLen);
	memcpy(pucPublicKey.e, rsaRefPublicKey.e, pucPublicKey.eLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_ExportEncPublicKey_RSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);

	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.m [param]:" << pucPublicKey.m << endl);
	TLOG_INFO("pucPublicKey.e [param]:" << pucPublicKey.e << endl);

	TLOG_INFO("End of exportEncPublicKey_RSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 产生RSA密钥对并输出
int KeyManageImp::generateKeyPair_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, Mitsurugi::Tars_RSArefPrivateKey& pucPrivateKey, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("generateKeyPair_RSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	pucPublicKey.mLen = 256;
	pucPublicKey.eLen = 256;

	pucPrivateKey.mLen = 256;
	pucPrivateKey.eLen = 256;
	pucPrivateKey.dLen = 256;
	pucPrivateKey.primePLen = 128;
	pucPrivateKey.primeQLen = 128;
	pucPrivateKey.pexpDpLen = 128;
	pucPrivateKey.pexpDqLen = 128;
	pucPrivateKey.coefLen = 128;

	RSArefPublicKey rsaRefPublicKey;

	RSArefPrivateKey rsaRefPrivateKey;

	int errorCode = SDF_GenerateKeyPair_RSA((void*)singleSessionPtr, uiKeyBits, &rsaRefPublicKey, &rsaRefPrivateKey);

	pucPublicKey.bits = rsaRefPublicKey.bits;
	memcpy(pucPublicKey.m, rsaRefPublicKey.m, pucPublicKey.mLen);
	memcpy(pucPublicKey.e, rsaRefPublicKey.e, pucPublicKey.eLen);

	pucPrivateKey.bits = rsaRefPrivateKey.bits;
	memcpy(pucPrivateKey.m, rsaRefPrivateKey.m, pucPrivateKey.mLen);
	memcpy(pucPrivateKey.e, rsaRefPrivateKey.e, pucPrivateKey.eLen);
	memcpy(pucPrivateKey.d, rsaRefPrivateKey.d, pucPrivateKey.dLen);
	memcpy(pucPrivateKey.primeP, rsaRefPrivateKey.prime[0], pucPrivateKey.primePLen);
	memcpy(pucPrivateKey.primeQ, rsaRefPrivateKey.prime[1], pucPrivateKey.primeQLen);
	memcpy(pucPrivateKey.pexpDp, rsaRefPrivateKey.pexp[0], pucPrivateKey.pexpDpLen);
	memcpy(pucPrivateKey.pexpDq, rsaRefPrivateKey.pexp[1], pucPrivateKey.pexpDqLen);
	memcpy(pucPrivateKey.coef, rsaRefPrivateKey.coef, pucPrivateKey.coefLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_GenerateKeyPair_RSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);

	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);
	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.m [param]:" << pucPublicKey.m << endl);
	TLOG_INFO("pucPublicKey.e [param]:" << pucPublicKey.e << endl);

	TLOG_INFO("pucPrivateKey.bits [param]:" << pucPrivateKey.bits << endl);
	TLOG_INFO("pucPrivateKey.m [param]:" << pucPrivateKey.m << endl);
	TLOG_INFO("pucPrivateKey.e [param]:" << pucPrivateKey.e << endl);
	TLOG_INFO("pucPrivateKey.d [param]:" << pucPrivateKey.d << endl);
	TLOG_INFO("pucPrivateKey.primeP [param]:" << pucPrivateKey.primeP << endl);
	TLOG_INFO("pucPrivateKey.primeQ [param]:" << pucPrivateKey.primeQ << endl);
	TLOG_INFO("pucPrivateKey.pexpDp [param]:" << pucPrivateKey.pexpDp << endl);
	TLOG_INFO("pucPrivateKey.pexpDq [param]:" << pucPrivateKey.pexpDq << endl);
	TLOG_INFO("pucPrivateKey.coef [param]:" << pucPrivateKey.coef << endl);

	TLOG_INFO("End of generateKeyPair_RSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 生成会话密钥并用内部RSA公钥加密输出
int KeyManageImp::generateKeyWithIPK_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiPKIIndex, tars::UInt32 uiKeyBits, vector<tars::UInt8>& pucKey, tars::UInt32& puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("generateKeyWithIPK_RSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	int* singleKeyHandlePtr = &(keyHandle.phKeyHandle);
	int** twoKeyHandlePtr = &(singleKeyHandlePtr);

	unsigned char PucKey[puiKeyLength];

	int errorCode = SDF_GenerateKeyWithIPK_RSA((void*)singleSessionPtr, uiPKIIndex, uiKeyBits, PucKey, puiKeyLength, (void**)twoKeyHandlePtr);

	pucKey.resize(puiKeyLength);

	for (char ch : PucKey)
	{
		pucKey.push_back(ch);
	}

	if (errorCode)
	{
		TLOG_ERROR("SDF_GenerateKeyWithIPK_RSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("keyHandle.phKeyHandle [param]:" << **twoKeyHandlePtr << endl);

	TLOG_INFO("uiPKIIndex [param]:" << uiPKIIndex << endl);
	TLOG_INFO("uiKeyBits [param]:" << uiKeyBits << endl);
	TLOG_INFO("PucKey [param]:" << PucKey << endl);
	TLOG_INFO("puiKeyLength [param]:" << puiKeyLength << endl);

	TLOG_INFO("End of generateKeyWithIPK_RSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 生成会话密钥并用外部RSA公钥加密输出
int KeyManageImp::generateKeyWithEPK_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, const Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, vector<tars::UInt8>& pucKey, tars::UInt32& puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("generateKeyWithEPK_RSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	int* singleKeyHandlePtr = &(keyHandle.phKeyHandle);
	int** twoKeyHandlePtr = &(singleKeyHandlePtr);

	RSArefPublicKey rsaRefPublicKey;

	rsaRefPublicKey.bits = pucPublicKey.bits;
	memcpy(rsaRefPublicKey.m, pucPublicKey.m, pucPublicKey.mLen);
	memcpy(rsaRefPublicKey.e, pucPublicKey.e, pucPublicKey.eLen);

	unsigned char PucKey[puiKeyLength];

	int errorCode = SDF_GenerateKeyWithEPK_RSA((void*)singleSessionPtr, uiKeyBits, &rsaRefPublicKey, PucKey, &puiKeyLength, (void**)twoKeyHandlePtr);

	pucKey.resize(puiKeyLength);

	for (char ch : PucKey)
	{
		pucKey.push_back(ch);
	}

	if (errorCode)
	{
		TLOG_ERROR("SDF_GenerateKeyWithEPK_RSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("keyHandle.phKeyHandle [param]:" << **twoKeyHandlePtr << endl);

	TLOG_INFO("uiKeyBits [param]:" << uiKeyBits << endl);
	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.m [param]:" << pucPublicKey.m << endl);
	TLOG_INFO("pucPublicKey.e [param]:" << pucPublicKey.e << endl);
	TLOG_INFO("PucKey [param]:" << PucKey << endl);
	TLOG_INFO("puiKeyLength [param]:" << puiKeyLength << endl);

	TLOG_INFO("End of generateKeyWithEPK_RSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 导入会话密钥并用内部RSA私钥解密
int KeyManageImp::importKeyWithISK_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, const vector<tars::UInt8>& pucKey, tars::UInt32 puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("importKeyWithISK_RSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	int* singleKeyHandlePtr = &(keyHandle.phKeyHandle);
	int** twoKeyHandlePtr = &(singleKeyHandlePtr);

	unsigned char PucKey[puiKeyLength];

	for (int i = 0; i < puiKeyLength; ++i)
	{
		PucKey[i] = pucKey[i];
	}

	int errorCode = SDF_ImportKeyWithISK_RSA((void*)singleSessionPtr, uiISKIndex, PucKey, puiKeyLength, (void**)twoKeyHandlePtr);

	if (errorCode)
	{
		TLOG_ERROR("SDF_ImportKeyWithISK_RSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("keyHandle.phKeyHandle [param]:" << **twoKeyHandlePtr << endl);

	TLOG_INFO("uiISKIndex [param]:" << uiISKIndex << endl);
	TLOG_INFO("PucKey [param]:" << PucKey << endl);
	TLOG_INFO("puiKeyLength [param]:" << puiKeyLength << endl);

	TLOG_INFO("End of importKeyWithISK_RSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 基于RSA算法的数字信封转换
int KeyManageImp::exchangeDigitEnvelopeBaseOnRSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, const Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, const vector<tars::UInt8>& pucDEInput, tars::UInt32 uiDELength, vector<tars::UInt8>& pucDEOutput, tars::UInt32& puiDELength, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("exchangeDigitEnvelopeBaseOnRSA() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	RSArefPublicKey rsaRefPublicKey;

	unsigned char PucDEInput[uiDELength];

	unsigned char PucDEOutput[puiDELength];

	RSArefPublicKey rsaRefPublicKey;

	rsaRefPublicKey.bits = pucPublicKey.bits;
	memcpy(rsaRefPublicKey.m, pucPublicKey.m, pucPublicKey.mLen);
	memcpy(rsaRefPublicKey.e, pucPublicKey.e, pucPublicKey.eLen);

	for (int i = 0; i < uiDELength; ++i)
	{
		PucDEInput[i] = pucDEInput[i];
	}

	int errorCode = SDF_ExchangeDigitEnvelopeBaseOnRSA((void*)singleSessionPtr, uiKeyIndex, &rsaRefPublicKey, PucDEInput, uiDELength, PucDEOutput, &puiDELength);

	pucDEOutput.resize(puiDELength);

	for (char ch : PucDEOutput)
	{
		pucDEOutput.push_back(ch);
	}

	if (errorCode)
	{
		TLOG_ERROR("SDF_ExchangeDigitEnvelopeBaseOnRSA error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);

	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);
	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.m [param]:" << pucPublicKey.m << endl);
	TLOG_INFO("pucPublicKey.e [param]:" << pucPublicKey.e << endl);

	TLOG_INFO("PucDEInput [param]:" << PucDEInput << endl);
	TLOG_INFO("uiDELength [param]:" << uiDELength << endl);
	TLOG_INFO("PucDEOutput [param]:" << PucDEOutput << endl);
	TLOG_INFO("puiDELength [param]:" << puiDELength << endl);

	TLOG_INFO("End of exchangeDigitEnvelopeBaseOnRSA() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 导出ECC签名公钥
int KeyManageImp::exportSignPublicKey_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("exportSignPublicKey_ECC() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	pucPublicKey.xLen = 64;
	pucPublicKey.yLen = 64;

	ECCrefPublicKey eccRefPublicKey;

	int errorCode = SDF_ExportSignPublicKey_ECC((void*)singleSessionPtr, uiKeyIndex, &eccRefPublicKey);

	pucPublicKey.bits = eccRefPublicKey.bits;
	memcpy(pucPublicKey.x, eccRefPublicKey.x, pucPublicKey.xLen);
	memcpy(pucPublicKey.y, eccRefPublicKey.y, pucPublicKey.yLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_ExportSignPublicKey_ECC error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);
	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.x [param]:" << pucPublicKey.x << endl);
	TLOG_INFO("pucPublicKey.y [param]:" << pucPublicKey.y << endl);

	TLOG_INFO("End of exportSignPublicKey_ECC() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 导出ECC加密公钥
int KeyManageImp::exportEncPublicKey_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("exportEncPublicKey_ECC() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	pucPublicKey.xLen = 64;
	pucPublicKey.yLen = 64;

	ECCrefPublicKey eccRefPublicKey;

	int errorCode = SDF_ExportEncPublicKey_ECC((void*)singleSessionPtr, uiKeyIndex, &eccRefPublicKey);

	pucPublicKey.bits = eccRefPublicKey.bits;
	memcpy(pucPublicKey.x, eccRefPublicKey.x, pucPublicKey.xLen);
	memcpy(pucPublicKey.y, eccRefPublicKey.y, pucPublicKey.yLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_ExportEncPublicKey_ECC error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);
	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.x [param]:" << pucPublicKey.x << endl);
	TLOG_INFO("pucPublicKey.y [param]:" << pucPublicKey.y << endl);

	TLOG_INFO("End of exportEncPublicKey_ECC() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 产生ECC密钥对并输出
int KeyManageImp::generateKeyPair_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiAlgID, tars::UInt32 uiKeyBits, Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, Mitsurugi::Tars_ECCrefPrivateKey& pucPrivateKey, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("generateKeyPair_ECC() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);
	
	pucPublicKey.xLen = 64;
	pucPublicKey.yLen = 64;

	pucPrivateKey.KLen = 64;

	ECCrefPublicKey eccRefPublicKey;

	ECCrefPrivateKey eccRefPrivateKey;

	int errorCode = SDF_GenerateKeyPair_ECC((void*)singleSessionPtr, uiAlgID, uiKeyBits, &eccRefPublicKey, &eccRefPrivateKey);

	pucPublicKey.bits = eccRefPublicKey.bits;
	memcpy(pucPublicKey.x, eccRefPublicKey.x, pucPublicKey.xLen);
	memcpy(pucPublicKey.y, eccRefPublicKey.y, pucPublicKey.yLen);

	pucPrivateKey.bits = eccRefPrivateKey.bits;
	memcpy(pucPrivateKey.K, eccRefPrivateKey.K, pucPrivateKey.KLen);

	if (errorCode) 
	{
		TLOG_ERROR("SDF_GenerateKeyPair_ECC error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("uiKeyIndex [param]:" << uiKeyIndex << endl);
	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.x [param]:" << pucPublicKey.x << endl);
	TLOG_INFO("pucPublicKey.y [param]:" << pucPublicKey.y << endl);

	TLOG_INFO("pucPrivateKey.bits [param]:" << pucPrivateKey.bits << endl);
	TLOG_INFO("pucPrivateKey.K [param]:" << pucPrivateKey.K << endl);

	TLOG_INFO("End of generateKeyPair_ECC() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 生成会话密钥并用内部ECC公钥加密输出
int KeyManageImp::generateKeyWithIPK_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiIPKIndex, tars::UInt32 uiKeyBits, Mitsurugi::Tars_ECCCipher& pucKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("generateKeyWithIPK_ECC() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	int* singleKeyHandlePtr = &(keyHandle.phKeyHandle);
	int** twoKeyHandlePtr = &(singleKeyHandlePtr);

	pucKey.xLen = 64;
	pucKey.yLen = 64;
	pucKey.MLen = 32;
	pucKey.CLen = 1;

	ECCCipher eccCipher;

	int errorCode = SDF_GenerateKeyWithIPK_ECC((void*)singleSessionPtr, uiIPKIndex, uiKeyBits, &eccCipher, (void**)twoKeyHandlePtr);

	memcpy(pucKey.x, eccCipher.x, pucKey.xLen);
	memcpy(pucKey.y, eccCipher.y, pucKey.yLen);
	memcpy(pucKey.M, eccCipher.M, pucKey.MLen);
	pucKey.L = eccCipher.L;
	memcpy(pucKey.C, eccCipher.C, pucKey.CLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_GenerateKeyWithIPK_ECC error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("keyHandle.phKeyHandle [param]:" << **twoKeyHandlePtr << endl);

	TLOG_INFO("uiIPKIndex [param]:" << uiIPKIndex << endl);
	TLOG_INFO("uiKeyBits [param]:" << uiKeyBits << endl);

	TLOG_INFO("pucKey.x [param]:" << pucKey.x << endl);
	TLOG_INFO("pucKey.y [param]:" << pucKey.y << endl);
	TLOG_INFO("pucKey.M [param]:" << pucKey.M << endl);
	TLOG_INFO("pucKey.L [param]:" << pucKey.L << endl);
	TLOG_INFO("pucKey.C [param]:" << pucKey.C << endl);

	TLOG_INFO("End of generateKeyWithIPK_ECC() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 生成会话密钥并用外部ECC公钥加密输出
int KeyManageImp::generateKeyWithEPK_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, tars::UInt32 uiAlgID, const Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, Mitsurugi::Tars_ECCCipher& pucKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	TLOG_INFO("============================================================================" << endl);

	TLOG_INFO("generateKeyWithEPK_ECC() is being called" << endl);

	int* singleSessionPtr = &(sessionHandle.phSessionHandle);

	int* singleKeyHandlePtr = &(keyHandle.phKeyHandle);
	int** twoKeyHandlePtr = &(singleKeyHandlePtr);

	pucKey.xLen = 64;
	pucKey.yLen = 64;
	pucKey.MLen = 32;
	pucKey.CLen = 1;

	ECCrefPublicKey eccRefPublicKey;
	ECCCipher eccCipher;

	eccRefPublicKey.bits = pucPublicKey.bits;
	memcpy(eccRefPublicKey.x, pucPublicKey.x, pucPublicKey.xLen);
	memcpy(eccRefPublicKey.y, pucPublicKey.y, pucPublicKey.yLen);

	int errorCode = SDF_GenerateKeyWithEPK_ECC((void*)singleSessionPtr, uiKeyBits, uiAlgID, &eccRefPublicKey, &eccCipher, (void**)twoKeyHandlePtr);

	memcpy(pucKey.x, eccCipher.x, pucKey.xLen);
	memcpy(pucKey.y, eccCipher.y, pucKey.yLen);
	memcpy(pucKey.M, eccCipher.M, pucKey.MLen);
	pucKey.L = eccCipher.L;
	memcpy(pucKey.C, eccCipher.C, pucKey.CLen);

	if (errorCode)
	{
		TLOG_ERROR("SDF_GenerateKeyWithEPK_ECC error" << endl);
		TLOG_ERROR("errorCode:" << errorCode << endl);
	}

	TLOG_INFO("sessionHandle.phSessionHandle [param]:" << *singleSessionPtr << endl);
	TLOG_INFO("keyHandle.phKeyHandle [param]:" << **twoKeyHandlePtr << endl);

	TLOG_INFO("uiKeyBits [param]:" << uiKeyBits << endl);
	TLOG_INFO("uiAlgID [param]:" << uiAlgID << endl);

	TLOG_INFO("pucPublicKey.bits [param]:" << pucPublicKey.bits << endl);
	TLOG_INFO("pucPublicKey.x [param]:" << pucPublicKey.x << endl);
	TLOG_INFO("pucPublicKey.y [param]:" << pucPublicKey.y << endl);

	TLOG_INFO("pucKey.x [param]:" << pucKey.x << endl);
	TLOG_INFO("pucKey.y [param]:" << pucKey.y << endl);
	TLOG_INFO("pucKey.M [param]:" << pucKey.M << endl);
	TLOG_INFO("pucKey.L [param]:" << pucKey.L << endl);
	TLOG_INFO("pucKey.C [param]:" << pucKey.C << endl);

	TLOG_INFO("End of generateKeyWithEPK_ECC() call" << endl);

	TLOG_INFO("============================================================================" << endl);

	return errorCode;
}

// 导入会话密钥并用内部ECC私钥解密
int KeyManageImp::importKeyWithISK_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, const Mitsurugi::Tars_ECCCipher& pucKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 生成密钥协商参数并输出
int KeyManageImp::generateAgreementDataWithECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, tars::UInt32 uiKeyBits, const vector<tars::UInt8>& pucSponsorID, tars::UInt32 uiSponsorIDLength, Mitsurugi::Tars_ECCrefPublicKey& pucSponsorPublicKey, Mitsurugi::Tars_ECCrefPublicKey& pucSponsorTmpPublicKey, Mitsurugi::PhAgreementHandle& agreementHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 计算会话密钥
int KeyManageImp::generateKeyWithECC(const Mitsurugi::PhSessionHandle& sessionHandle, const vector<tars::UInt8>& pucResponseID, tars::UInt32 uiResponseIDLength, const Mitsurugi::Tars_ECCrefPublicKey& pucResponsePublicKey, const Mitsurugi::Tars_ECCrefPublicKey& pucResponseTmpPublicKey, const Mitsurugi::PhAgreementHandle& agreementHandle, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 产生协商数据并计算会话密钥
int KeyManageImp::generateAgreementDataAndKeyWithECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, tars::UInt32 uiKeyBits, const vector<tars::UInt8>& pucResponseID, tars::UInt32 uiResponseIDLength, const vector<tars::UInt8>& pucSponsorID, tars::UInt32 uiSponsorIDLength, const Mitsurugi::Tars_ECCrefPublicKey& pucSponsorPublicKey, const Mitsurugi::Tars_ECCrefPublicKey& pucSponsorTmpPublicKey, Mitsurugi::Tars_ECCrefPublicKey& pucResponsePublicKey, Mitsurugi::Tars_ECCrefPublicKey& pucResponseTmpPublicKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 基于ECC算法的数字信封转换
int KeyManageImp::exchangeDigitEncelopeBaseOnECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, tars::UInt32 uiAlgID, const Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, const Mitsurugi::Tars_ECCCipher& pucEncDataIn, Mitsurugi::Tars_ECCCipher& pucEncDataOut, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 生成会话密钥并用密钥加密密钥加密输出
int KeyManageImp::generateKeyWithKEK(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, tars::UInt32 uiAlgID, tars::UInt32 uiKEKIndex, vector<tars::UInt8>& pucKey, tars::UInt32& puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 导入会话密钥并用密钥加密密钥解密
int KeyManageImp::importKeyWithKEK(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiAlgID, tars::UInt32 uiKEKIndex, const vector<tars::UInt8>& pucKey, tars::UInt32 puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 导入明文会话密钥
int KeyManageImp::importKey(const Mitsurugi::PhSessionHandle& sessionHandle, const vector<tars::UInt8>& pucKey, tars::UInt32 uiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

// 销毁会话密钥
int KeyManageImp::destroyKey(const Mitsurugi::PhSessionHandle& sessionHandle, const Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_)
{
	return 0;
}

