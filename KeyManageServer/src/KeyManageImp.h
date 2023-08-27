#ifndef _KeyManageImp_H_
#define _KeyManageImp_H_

#include "servant/Application.h"
#include "KeyManage.h"

/**
 *
 *
 */
class KeyManageImp : public Mitsurugi::KeyManage
{
public:
    /**
     *
     */
    virtual ~KeyManageImp() {}

    /**
     *
     */
    virtual void initialize();

    /**
     *
     */
    virtual void destroy();

    /**
     *
     */
    // 导出RSA签名公钥
    virtual int exportSignPublicKey_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_);

    // 导出RSA加密公钥
    virtual int exportEncPublicKey_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_);

    // 产生RSA密钥对并输出
    virtual int generateKeyPair_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, Mitsurugi::Tars_RSArefPrivateKey& pucPrivateKey, tars::TarsCurrentPtr _current_);

    // 生成会话密钥并用内部RSA公钥加密输出
    virtual int generateKeyWithIPK_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiPKIIndex, tars::UInt32 uiKeyBits, vector<tars::UInt8>& pucKey, tars::UInt32& puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 生成会话密钥并用外部RSA公钥加密输出
    virtual int generateKeyWithEPK_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, const Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, vector<tars::UInt8>& pucKey, tars::UInt32& puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 导入会话密钥并用内部RSA私钥解密
    virtual int importKeyWithISK_RSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, const vector<tars::UInt8>& pucKey, tars::UInt32 puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 基于RSA算法的数字信封转换
    virtual int exchangeDigitEnvelopeBaseOnRSA(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, const Mitsurugi::Tars_RSArefPublicKey& pucPublicKey, const vector<tars::UInt8>& pucDEInput, tars::UInt32 uiDELength, vector<tars::UInt8>& pucDEOutput, tars::UInt32& puiDELength, tars::TarsCurrentPtr _current_);

    // 导出ECC签名公钥
    virtual int exportSignPublicKey_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_);

    // 导出ECC加密公钥
    virtual int exportEncPublicKey_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, tars::TarsCurrentPtr _current_);

    // 产生ECC密钥对并输出
    virtual int generateKeyPair_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiAlgID, tars::UInt32 uiKeyBits, Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, Mitsurugi::Tars_ECCrefPrivateKey& pucPrivateKey, tars::TarsCurrentPtr _current_);

    // 生成会话密钥并用内部ECC公钥加密输出
    virtual int generateKeyWithIPK_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiIPKIndex, tars::UInt32 uiKeyBits, Mitsurugi::Tars_ECCCipher& pucKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 生成会话密钥并用外部ECC公钥加密输出
    virtual int generateKeyWithEPK_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, tars::UInt32 uiAlgID, const Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, Mitsurugi::Tars_ECCCipher& pucKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 导入会话密钥并用内部ECC私钥解密
    virtual int importKeyWithISK_ECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, const Mitsurugi::Tars_ECCCipher& pucKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 生成密钥协商参数并输出
    virtual int generateAgreementDataWithECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, tars::UInt32 uiKeyBits, const vector<tars::UInt8>& pucSponsorID, tars::UInt32 uiSponsorIDLength, Mitsurugi::Tars_ECCrefPublicKey& pucSponsorPublicKey, Mitsurugi::Tars_ECCrefPublicKey& pucSponsorTmpPublicKey, Mitsurugi::PhAgreementHandle& agreementHandle, tars::TarsCurrentPtr _current_);

    // 计算会话密钥
    virtual int generateKeyWithECC(const Mitsurugi::PhSessionHandle& sessionHandle, const vector<tars::UInt8>& pucResponseID, tars::UInt32 uiResponseIDLength, const Mitsurugi::Tars_ECCrefPublicKey& pucResponsePublicKey, const Mitsurugi::Tars_ECCrefPublicKey& pucResponseTmpPublicKey, const Mitsurugi::PhAgreementHandle& agreementHandle, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 产生协商数据并计算会话密钥
    virtual int generateAgreementDataAndKeyWithECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiISKIndex, tars::UInt32 uiKeyBits, const vector<tars::UInt8>& pucResponseID, tars::UInt32 uiResponseIDLength, const vector<tars::UInt8>& pucSponsorID, tars::UInt32 uiSponsorIDLength, const Mitsurugi::Tars_ECCrefPublicKey& pucSponsorPublicKey, const Mitsurugi::Tars_ECCrefPublicKey& pucSponsorTmpPublicKey, Mitsurugi::Tars_ECCrefPublicKey& pucResponsePublicKey, Mitsurugi::Tars_ECCrefPublicKey& pucResponseTmpPublicKey, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 基于ECC算法的数字信封转换
    virtual int exchangeDigitEncelopeBaseOnECC(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyIndex, tars::UInt32 uiAlgID, const Mitsurugi::Tars_ECCrefPublicKey& pucPublicKey, const Mitsurugi::Tars_ECCCipher& pucEncDataIn, Mitsurugi::Tars_ECCCipher& pucEncDataOut, tars::TarsCurrentPtr _current_);

    // 生成会话密钥并用密钥加密密钥加密输出
    virtual int generateKeyWithKEK(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiKeyBits, tars::UInt32 uiAlgID, tars::UInt32 uiKEKIndex, vector<tars::UInt8>& pucKey, tars::UInt32& puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 导入会话密钥并用密钥加密密钥解密
    virtual int importKeyWithKEK(const Mitsurugi::PhSessionHandle& sessionHandle, tars::UInt32 uiAlgID, tars::UInt32 uiKEKIndex, const vector<tars::UInt8>& pucKey, tars::UInt32 puiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 导入明文会话密钥
    virtual int importKey(const Mitsurugi::PhSessionHandle& sessionHandle, const vector<tars::UInt8>& pucKey, tars::UInt32 uiKeyLength, Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

    // 销毁会话密钥
    virtual int destroyKey(const Mitsurugi::PhSessionHandle& sessionHandle, const Mitsurugi::PhKeyHandle& keyHandle, tars::TarsCurrentPtr _current_);

};
/////////////////////////////////////////////////////
#endif
