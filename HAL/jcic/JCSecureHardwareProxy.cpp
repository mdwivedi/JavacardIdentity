/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "JCSecureHardwareProxy"
#define ENABLE_JAVA_CARD_PROVISIONING 1
#define ENABLE_JAVA_CARD_PRESENTATION 1

#include <android/hardware/identity/support/IdentityCredentialSupport.h>

#include <android/log.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/properties.h>
#include <string.h>

#include <openssl/sha.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#ifdef ENABLE_JAVA_CARD_PROVISIONING
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>
#include "AppletConnection.h"
#include <cmath>
#else
#include <libeic.h>
#endif

#include "JCSecureHardwareProxy.h"

#define  ALOG(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)

using ::std::optional;
using ::std::string;
using ::std::tuple;
using ::std::vector;

namespace android::hardware::identity {
// ----------------------------------------------------------------------
#ifdef ENABLE_JAVA_CARD_PROVISIONING
void printByteArray(const uint8_t* byteBuffer, size_t size) {

    char outBuff[(256 * 2) + 1];
    outBuff[(256 * 2)] = '\0';
    size_t noOfPrints = std::ceil(static_cast<float>(size) / 256);
    size_t i = 0, j = 0;
    for (i = 0; i < size && j < noOfPrints; i++) {
        if(j < noOfPrints && (i - j*256) < (256 - 1)) {
            sprintf(&outBuff[(i - j*256)*2], "%02X", byteBuffer[i]);
        } else {
            sprintf(&outBuff[(i - j*256)*2], "%02X", byteBuffer[i]);
            outBuff[(i - j*256)*2 + 2] = '\0';
            ALOG("%s", outBuff);
            j++;
        }
    }
    if((i - j*256) <= (256 - 1)) {
        outBuff[(i - j*256)*2 + 1] = '\0';
    }
    ALOG("%s", outBuff);

}
#endif

JCSecureHardwareProxy::JCSecureHardwareProxy() {}

JCSecureHardwareProxy::~JCSecureHardwareProxy() {
    mAppletConnection.close();
}

bool JCSecureHardwareProxy::getHardwareInfo(string* storeName, string* storeAuthorName,
                                 int32_t* gcmChunkSize, bool* isDirectAccess, vector<string>* supportedDocTypes) {
    LOG(INFO) << "JCSecureHardwareProxy getHardwareInfo";
#ifdef ENABLE_JAVA_CARD_PROVISIONING
    if (!mAppletConnection.connectToTransportClient()) {
        return false;
    }

    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return false;
        }
    }

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_GET_HARDWARE_INFO, 0, 0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    LOG(INFO) << "INS_ICS_GET_HARDWARE_INFO returned response size " << response.dataSize();
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO response is not an array with two elements";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO response is not success";
        return false;
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    if (returnArray == nullptr || returnArray->size() != 5) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO returned invalid response";
        return false;
    }
    const cppbor::Tstr* cborStoreName = (*returnArray)[0]->asTstr();
    *storeName = std::string(cborStoreName->value());
    const cppbor::Tstr* cborStoreAuthorName = (*returnArray)[1]->asTstr();
    *storeAuthorName = std::string(cborStoreAuthorName->value());
    const cppbor::Uint* cborGsmChunkSize = (*returnArray)[2]->asUint();
    LOG(INFO) << "INS_ICS_GET_HARDWARE_INFO gcmChunkSize : " << cborGsmChunkSize->value();
    *gcmChunkSize = cborGsmChunkSize->value();
    const cppbor::Simple* cborIsDirectAccess = (*returnArray)[3]->asSimple();
    *isDirectAccess = (cborIsDirectAccess->asBool())->value();
    const cppbor::Array* cborSupportedDotTypes = (*returnArray)[4]->asArray();
    if(cborSupportedDotTypes->size() > 0) {
        vector<std::string> docTypeVec(cborSupportedDotTypes->size());
        for(size_t i = 0; i < cborSupportedDotTypes->size(); i++) {
            docTypeVec[i] = std::string(((*cborSupportedDotTypes)[i]->asTstr())->value());
        }
        *supportedDocTypes = docTypeVec;
    } else {
        vector<std::string> emptyVec(0);
        *supportedDocTypes = emptyVec;
    }

    return true;
#else
    return false;
#endif
}

JCSecureHardwareProxy::JCSecureHardwareProxy() {}

JCSecureHardwareProxy::~JCSecureHardwareProxy() {
    mAppletConnection.close();
}

bool JCSecureHardwareProxy::getHardwareInfo(string* storeName, string* storeAuthorName,
                                 int32_t* gcmChunkSize, bool* isDirectAccess, vector<string>* supportedDocTypes) {
    LOG(INFO) << "JCSecureHardwareProxy getHardwareInfo";
#ifdef ENABLE_JAVA_CARD
    if (!mAppletConnection.connectToTransportClient()) {
        return false;
    }

    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return false;
        }
    }

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_GET_HARDWARE_INFO, 0, 0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    LOG(INFO) << "INS_ICS_GET_HARDWARE_INFO returned response size " << response.dataSize();
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO response is not an array with two elements";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO response is not success";
        return false;
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    if (returnArray == nullptr || returnArray->size() != 5) {
        LOG(ERROR) << "INS_ICS_GET_HARDWARE_INFO returned invalid response";
        return false;
    }
    const cppbor::Tstr* cborStoreName = (*returnArray)[0]->asTstr();
    *storeName = std::string(cborStoreName->value());
    const cppbor::Tstr* cborStoreAuthorName = (*returnArray)[1]->asTstr();
    *storeAuthorName = std::string(cborStoreAuthorName->value());
    const cppbor::Uint* cborGsmChunkSize = (*returnArray)[2]->asUint();
    LOG(INFO) << "INS_ICS_GET_HARDWARE_INFO gcmChunkSize : " << cborGsmChunkSize->value();
    *gcmChunkSize = cborGsmChunkSize->value();
    const cppbor::Simple* cborIsDirectAccess = (*returnArray)[3]->asSimple();
    *isDirectAccess = (cborIsDirectAccess->asBool())->value();
    const cppbor::Array* cborSupportedDotTypes = (*returnArray)[4]->asArray();
    if(cborSupportedDotTypes->size() > 0) {
        vector<std::string> docTypeVec(cborSupportedDotTypes->size());
        for(size_t i = 0; i < cborSupportedDotTypes->size(); i++) {
            docTypeVec[i] = std::string(((*cborSupportedDotTypes)[i]->asTstr())->value());
        }
        *supportedDocTypes = docTypeVec;
    } else {
        vector<std::string> emptyVec(0);
        *supportedDocTypes = emptyVec;
    }

    return true;
#else
    return false;
#endif
}

JCSecureHardwareProvisioningProxy::JCSecureHardwareProvisioningProxy() {}

JCSecureHardwareProvisioningProxy::~JCSecureHardwareProvisioningProxy() {
    mAppletConnection.close();
}

bool JCSecureHardwareProvisioningProxy::shutdown() {
    LOG(INFO) << "JCSecureHardwareProvisioningProxy shutdown";
    mAppletConnection.close();
    return true;
}

bool JCSecureHardwareProvisioningProxy::initialize(bool testCredential) {
    LOG(INFO) << "JCSecureHardwareProvisioningProxy created, sizeof(EicProvisioning): "
              << sizeof(EicProvisioning);
#ifdef ENABLE_JAVA_CARD_PROVISIONING
	isTestCredential = testCredential;
    if (!mAppletConnection.connectToTransportClient()) {
        return false;
    }

    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return false;
        }
    }

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_PROVISIONING_INIT, 0,
                        testCredential};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_PROVISIONING_INIT response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_PROVISIONING_INIT response is not an array with one elements";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_PROVISIONING_INIT response is not success";
        return false;
    }
    return true;
#else
    return eicProvisioningInit(&ctx_, testCredential);
#endif
}

bool JCSecureHardwareProvisioningProxy::initializeForUpdate(
        bool testCredential, string docType, vector<uint8_t> encryptedCredentialKeys) {
#ifdef ENABLE_JAVA_CARD_PROVISIONING
        return false;
#else
    return eicProvisioningInitForUpdate(&ctx_, testCredential, docType.c_str(),
                                        encryptedCredentialKeys.data(),
                                        encryptedCredentialKeys.size());
#endif
}

// Returns public key certificate.
optional<vector<uint8_t>> JCSecureHardwareProvisioningProxy::createCredentialKey(
        const vector<uint8_t>& challenge, const vector<uint8_t>& applicationId) {
    LOG(INFO) << "JCSecureHardwareProvisioningProxy createCredentialKey ";
#ifdef ENABLE_JAVA_CARD_PROVISIONING

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_CREATE_CREDENTIAL_KEY, 0, 0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_CREATE_CREDENTIAL_KEY response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_CREATE_CREDENTIAL_KEY response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_CREATE_CREDENTIAL_KEY response is not success";
        return {};
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* pubKeyBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> pubKey = pubKeyBstr->value();
    //TODO currently attestation certificate is created from SoftKeyMaster, we need to get from applet.
    optional<vector<vector<uint8_t>>> certChain =  android::hardware::identity::support::createAttestationForEcPublicKey(
                    pubKey, challenge, applicationId, isTestCredential);
    // Extract certificate chain.
    vector<uint8_t> pubKeyCert =
            android::hardware::identity::support::certificateChainJoin(certChain.value());
    LOG(INFO) << "INS_ICS_CREATE_CREDENTIAL_KEY attested certificate from SoftKeyMaster :";
    printByteArray(pubKeyCert.data(), pubKeyCert.size());

    return pubKeyCert;
#else
    uint8_t publicKeyCert[4096];
    size_t publicKeyCertSize = sizeof publicKeyCert;
    if (!eicProvisioningCreateCredentialKey(&ctx_, challenge.data(), challenge.size(),
                                            applicationId.data(), applicationId.size(),
                                            publicKeyCert, &publicKeyCertSize)) {
        return {};
    }
    vector<uint8_t> pubKeyCert(publicKeyCertSize);
    memcpy(pubKeyCert.data(), publicKeyCert, publicKeyCertSize);
    return pubKeyCert;
#endif
}

bool JCSecureHardwareProvisioningProxy::startPersonalization(
        int accessControlProfileCount, vector<int> entryCounts, const string& docType,
        size_t expectedProofOfProvisioningSize) {
    LOG(INFO) << "JJCSecureHardwareProvisioningProxy::startPersonalization ";

#ifdef ENABLE_JAVA_CARD_PROVISIONING
    cppbor::Array pArray;
    cppbor::Array entryCountArray;
    for (auto id : entryCounts) {
        entryCountArray.add(id);
    }
    pArray.add(docType)
            .add(accessControlProfileCount)
            .add(std::move(entryCountArray))
            .add(expectedProofOfProvisioningSize);
    vector<uint8_t> encodedCbor = pArray.encode();

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_START_PERSONALIZATION, 0,
                        0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_START_PERSONALIZATION response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_START_PERSONALIZATION response is not an array with one elements";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_START_PERSONALIZATION response is not success";
        return false;
    }
    return true;
#else

    if (!eicProvisioningStartPersonalization(&ctx_, accessControlProfileCount, entryCounts.data(),
                                             entryCounts.size(), docType.c_str(),
                                             expectedProofOfProvisioningSize)) {
        return false;
    }
    return true;
#endif
}

// Returns MAC (28 bytes).
optional<vector<uint8_t>> JCSecureHardwareProvisioningProxy::addAccessControlProfile(
        int id, const vector<uint8_t>& readerCertificate, bool userAuthenticationRequired,
        uint64_t timeoutMillis, uint64_t secureUserId) {

#ifdef ENABLE_JAVA_CARD_PROVISIONING
    LOG(INFO) << "JJCSecureHardwareProvisioningProxy::addAccessControlProfile ";

    cppbor::Array pArray;
    pArray.add(id)
            .add(userAuthenticationRequired)
            .add(timeoutMillis)
            .add(secureUserId)
            .add(std::move(readerCertificate));
    vector<uint8_t> encodedCbor = pArray.encode();

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_ADD_ACCESS_CONTROL_PROFILE, 0,
                        0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_ADD_ACCESS_CONTROL_PROFILE response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_ADD_ACCESS_CONTROL_PROFILE response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_ADD_ACCESS_CONTROL_PROFILE response is not success";
        return {};
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* macBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> mac = macBstr->value();
    if(mac.size() != 28) {
        LOG(ERROR) << "INS_ICS_ADD_ACCESS_CONTROL_PROFILE returned invalid size of mac " << mac.size();
        return {};
    }

    return mac;
#else
    vector<uint8_t> mac(28);
    if (!eicProvisioningAddAccessControlProfile(
                &ctx_, id, readerCertificate.data(), readerCertificate.size(),
                userAuthenticationRequired, timeoutMillis, secureUserId, mac.data())) {
        return {};
    }
    return mac;
#endif
}

bool JCSecureHardwareProvisioningProxy::beginAddEntry(const vector<int>& accessControlProfileIds,
                                                        const string& nameSpace, const string& name,
                                                        uint64_t entrySize) {
#ifdef ENABLE_JAVA_CARD_PROVISIONING
    LOG(INFO) << "JJCSecureHardwareProvisioningProxy::beginAddEntry ";

    cppbor::Array cborProfileIDs;
    for(size_t i = 0; i < accessControlProfileIds.size(); i++) {
        cborProfileIDs.add(accessControlProfileIds[i]);
    }

    cppbor::Array pArray;
    pArray.add(nameSpace)
            .add(name)
            .add(std::move(cborProfileIDs))
            .add(entrySize);
    vector<uint8_t> encodedCbor = pArray.encode();

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_BEGIN_ADD_ENTRY, 0,
                        0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }

    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_BEGIN_ADD_ENTRY response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_BEGIN_ADD_ENTRY response is not an array with one elements";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_BEGIN_ADD_ENTRY response is not success";
        return false;
    }
    return true;
#else
    uint8_t scratchSpace[512];
    return eicProvisioningBeginAddEntry(&ctx_, accessControlProfileIds.data(),
                                        accessControlProfileIds.size(), nameSpace.c_str(),
                                        name.c_str(), entrySize, scratchSpace, sizeof scratchSpace);
#endif
}

// Returns encryptedContent.
optional<vector<uint8_t>> JCSecureHardwareProvisioningProxy::addEntryValue(
        const vector<int>& accessControlProfileIds, const string& nameSpace, const string& name,
        const vector<uint8_t>& content) {
#ifdef ENABLE_JAVA_CARD_PROVISIONING
    LOG(INFO) << "JJCSecureHardwareProvisioningProxy::addEntryValue ";

    cppbor::Array cborProfileIDs;
    for(size_t i = 0; i < accessControlProfileIds.size(); i++) {
        cborProfileIDs.add(accessControlProfileIds[i]);
    }
    cppbor::Array additionalDataArray;
    additionalDataArray.add(nameSpace)
            .add(name)
            .add(std::move(cborProfileIDs));
    cppbor::Array pArray;
    pArray.add(std::move(additionalDataArray))
        .add(std::move(content));
    vector<uint8_t> encodedCbor = pArray.encode();

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_ADD_ENTRY_VALUE, 0,
                        0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_ADD_ENTRY_VALUE response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_ADD_ENTRY_VALUE response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_ADD_ENTRY_VALUE response is not success";
        return {};
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* encryptedContentBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> encryptedContent = encryptedContentBstr->value();
    if(encryptedContent.size() != content.size() + 28) {
        LOG(ERROR) << "INS_ICS_ADD_ENTRY_VALUE returned invalid size of encrypted content.";
        return {};
    }

    return encryptedContent;
#else
    vector<uint8_t> eicEncryptedContent;
    uint8_t scratchSpace[512];
    eicEncryptedContent.resize(content.size() + 28);
    if (!eicProvisioningAddEntryValue(
                &ctx_, accessControlProfileIds.data(), accessControlProfileIds.size(),
                nameSpace.c_str(), name.c_str(), content.data(), content.size(),
                eicEncryptedContent.data(), scratchSpace, sizeof scratchSpace)) {
        return {};
    }
    return eicEncryptedContent;
#endif
}

// Returns signatureOfToBeSigned (EIC_ECDSA_P256_SIGNATURE_SIZE bytes).
optional<vector<uint8_t>> JCSecureHardwareProvisioningProxy::finishAddingEntries() {
    vector<uint8_t> signatureOfToBeSigned(EIC_ECDSA_P256_SIGNATURE_SIZE);
#ifdef ENABLE_JAVA_CARD_PROVISIONING
    LOG(INFO) << "JJCSecureHardwareProvisioningProxy::finishAddingEntries ";

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_FINISH_ADDING_ENTRIES, 0,
                        0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES response is not success";
        return {};
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* signatureOfToBeSignedBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> derSignature = signatureOfToBeSignedBstr->value();

    ECDSA_SIG* sig;
    const unsigned char* p = derSignature.data();
    sig = d2i_ECDSA_SIG(nullptr, &p, derSignature.size());
    if (sig == nullptr) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES Error decoding DER signature";
        return {};
    }

    if (BN_bn2binpad(sig->r, signatureOfToBeSigned.data(), 32) != 32) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES Error encoding r";
        return {};
    }
    if (BN_bn2binpad(sig->s, signatureOfToBeSigned.data() + 32, 32) != 32) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES Error encoding s";
        return {};
    }

#else
    if (!eicProvisioningFinishAddingEntries(&ctx_, signatureOfToBeSigned.data())) {
        return {};
    }
#endif
    return signatureOfToBeSigned;
}

// Returns encryptedCredentialKeys.
optional<vector<uint8_t>> JCSecureHardwareProvisioningProxy::finishGetCredentialData(
        const string& docType) {
#ifdef ENABLE_JAVA_CARD_PROVISIONING
    LOG(INFO) << "JJCSecureHardwareProvisioningProxy::finishGetCredentialData ";
    cppbor::Array pArray;
    pArray.add(docType);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_FINISH_GET_CREDENTIAL_DATA, 0,
                        0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_FINISH_GET_CREDENTIAL_DATA response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_FINISH_GET_CREDENTIAL_DATA response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_FINISH_GET_CREDENTIAL_DATA response is not success";
        return {};
    }
    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* encryptedCredentialKeysBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> encryptedCredentialKeys = encryptedCredentialKeysBstr->value();

    return encryptedCredentialKeys;
#else
    vector<uint8_t> encryptedCredentialKeys(116);
    size_t size = encryptedCredentialKeys.size();
    if (!eicProvisioningFinishGetCredentialData(&ctx_, docType.c_str(),
                                                encryptedCredentialKeys.data(), &size)) {
        return {};
    }
    encryptedCredentialKeys.resize(size);
    return encryptedCredentialKeys;
#endif
}

// ----------------------------------------------------------------------

JCSecureHardwarePresentationProxy::JCSecureHardwarePresentationProxy() {}

JCSecureHardwarePresentationProxy::~JCSecureHardwarePresentationProxy() {
    mAppletConnection.close();
}

bool JCSecureHardwarePresentationProxy::initialize(bool testCredential, string docType,
                                                     vector<uint8_t> encryptedCredentialKeys) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy created, sizeof(EicPresentation): "
              << sizeof(EicPresentation);
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    if (!mAppletConnection.connectToTransportClient()) {
        return false;
    }

    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return false;
        }
    }

    cppbor::Array pArray;
    pArray.add(docType)
        .add(std::move(encryptedCredentialKeys));
    vector<uint8_t> encodedCbor = pArray.encode();

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_PRESENTATION_INIT, 0, testCredential, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_PRESENTATION_INIT response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_PRESENTATION_INIT response is not an array with one elements";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_PRESENTATION_INIT response is not success";
        return false;
    }
    return true;
#else
    return eicPresentationInit(&ctx_, testCredential, docType.c_str(),
                               encryptedCredentialKeys.data(), encryptedCredentialKeys.size());
#endif
}

// Returns publicKeyCert (1st component) and signingKeyBlob (2nd component)
optional<pair<vector<uint8_t>, vector<uint8_t>>>
JCSecureHardwarePresentationProxy::generateSigningKeyPair(string docType, time_t now) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy generateSigningKeyPair called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION

    cppbor::Array pArray;
    pArray.add(docType)
        .add(now);
    vector<uint8_t> encodedCbor = pArray.encode();

    // Send the command to the applet to create a new credential
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_GENERATE_SIGNING_KEY_PAIR, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_GENERATE_SIGNING_KEY_PAIR response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_GENERATE_SIGNING_KEY_PAIR response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_GENERATE_SIGNING_KEY_PAIR response is not success";
        return {};
    }

    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* pubKeyBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> publicKeyCert = pubKeyBstr->value();
    const cppbor::Bstr* signingKeyBlobBstr = (*returnArray)[1]->asBstr();
    const vector<uint8_t> signingKeyBlob = signingKeyBlobBstr->value();

    LOG(INFO) << "INS_ICS_GENERATE_SIGNING_KEY_PAIR generated certificate :";
    printByteArray(publicKeyCert.data(), publicKeyCert.size());

    return std::make_pair(publicKeyCert, signingKeyBlob);
#else
    uint8_t publicKeyCert[512];
    size_t publicKeyCertSize = sizeof(publicKeyCert);
    vector<uint8_t> signingKeyBlob(60);

    if (!eicPresentationGenerateSigningKeyPair(&ctx_, docType.c_str(), now, publicKeyCert,
                                               &publicKeyCertSize, signingKeyBlob.data())) {
        return {};
    }

    vector<uint8_t> cert;
    cert.resize(publicKeyCertSize);
    memcpy(cert.data(), publicKeyCert, publicKeyCertSize);

    return std::make_pair(cert, signingKeyBlob);
#endif
}

// Returns private key
optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::createEphemeralKeyPair() {
    LOG(INFO) << "JCSecureHardwarePresentationProxy createEphemeralKeyPair called";
    vector<uint8_t> priv(EIC_P256_PRIV_KEY_SIZE);
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_CREATE_EPHEMERAL_KEY_PAIR, 0, 0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_CREATE_EPHEMERAL_KEY_PAIR response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_CREATE_EPHEMERAL_KEY_PAIR response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_CREATE_EPHEMERAL_KEY_PAIR response is not success";
        return {};
    }

    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* privKeyBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> privKey = privKeyBstr->value();

    if(privKey.size() != EIC_P256_PRIV_KEY_SIZE) {
        LOG(ERROR) << "INS_ICS_CREATE_EPHEMERAL_KEY_PAIR invalid key size is returned - " << privKey.size();
        return {};
    }
    memcpy(priv.data(), privKey.data(), privKey.size());
#else
    if (!eicPresentationCreateEphemeralKeyPair(&ctx_, priv.data())) {
        return {};
    }
#endif
    return priv;
}

optional<uint64_t> JCSecureHardwarePresentationProxy::createAuthChallenge() {
    LOG(INFO) << "JCSecureHardwarePresentationProxy createAuthChallenge called";
    uint64_t challenge;
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_CREATE_AUTH_CHALLENGE, 0, 0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_CREATE_AUTH_CHALLENGE response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_CREATE_AUTH_CHALLENGE response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_CREATE_AUTH_CHALLENGE response is not success";
        return {};
    }

    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Uint* challengeUint = (*returnArray)[0]->asUint();
    challenge = challengeUint->value();

#else
    if (!eicPresentationCreateAuthChallenge(&ctx_, &challenge)) {
        return {};
    }
#endif
    return challenge;
}

bool JCSecureHardwarePresentationProxy::shutdown() {
    LOG(INFO) << "JCSecureHardwarePresentationProxy shutdown";
    return true;
}

bool JCSecureHardwarePresentationProxy::pushReaderCert(const vector<uint8_t>& certX509) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy pushReaderCert called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    cppbor::Array pArray;
    pArray.add(certX509);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_PUSH_READER_CERT, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_PUSH_READER_CERT response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_PUSH_READER_CERT response is not an array with one element";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_PUSH_READER_CERT response is not success";
        return false;
    }

    return true;
#else
    return eicPresentationPushReaderCert(&ctx_, certX509.data(), certX509.size());
#endif
}

bool JCSecureHardwarePresentationProxy::validateRequestMessage(
        const vector<uint8_t>& sessionTranscript, const vector<uint8_t>& requestMessage,
        int coseSignAlg, const vector<uint8_t>& readerSignatureOfToBeSigned) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy validateRequestMessage called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION
	vector<uint8_t> readerSignatureOfTBSDer;
	if(!android::hardware::identity::support::ecdsaSignatureCoseToDer(readerSignatureOfToBeSigned, readerSignatureOfTBSDer)) {
		return false;
	}
    cppbor::Array pArray;
    pArray.add(sessionTranscript)
		.add(requestMessage)
		.add(coseSignAlg)
		.add(readerSignatureOfTBSDer);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_VALIDATE_REQUEST_MESSAGE, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_VALIDATE_REQUEST_MESSAGE response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_VALIDATE_REQUEST_MESSAGE response is not an array with one element";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_VALIDATE_REQUEST_MESSAGE response is not success";
        return false;
    }

    return true;
#else
    return eicPresentationValidateRequestMessage(
            &ctx_, sessionTranscript.data(), sessionTranscript.size(), requestMessage.data(),
            requestMessage.size(), coseSignAlg, readerSignatureOfToBeSigned.data(),
            readerSignatureOfToBeSigned.size());
#endif
}

bool JCSecureHardwarePresentationProxy::setAuthToken(
        uint64_t challenge, uint64_t secureUserId, uint64_t authenticatorId,
        int hardwareAuthenticatorType, uint64_t timeStamp, const vector<uint8_t>& mac,
        uint64_t verificationTokenChallenge, uint64_t verificationTokenTimestamp,
        int verificationTokenSecurityLevel, const vector<uint8_t>& verificationTokenMac) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy setAuthToken called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    cppbor::Array pArray;
    pArray.add(challenge)
        .add(secureUserId)
        .add(authenticatorId)
        .add(hardwareAuthenticatorType)
        .add(timeStamp)
        .add(mac)
        .add(verificationTokenChallenge)
        .add(verificationTokenTimestamp)
        .add(verificationTokenSecurityLevel)
        .add(verificationTokenMac);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_SET_AUTH_TOKEN, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_SET_AUTH_TOKEN response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_SET_AUTH_TOKEN response is not an array with one element";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_SET_AUTH_TOKEN response is not success";
        return false;
    }

    return true;
#else
    return eicPresentationSetAuthToken(&ctx_, challenge, secureUserId, authenticatorId,
                                       hardwareAuthenticatorType, timeStamp, mac.data(), mac.size(),
                                       verificationTokenChallenge, verificationTokenTimestamp,
                                       verificationTokenSecurityLevel, verificationTokenMac.data(),
                                       verificationTokenMac.size());
#endif
}

optional<bool> JCSecureHardwarePresentationProxy::validateAccessControlProfile(
        int id, const vector<uint8_t>& readerCertificate, bool userAuthenticationRequired,
        int timeoutMillis, uint64_t secureUserId, const vector<uint8_t>& mac) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy validateAccessControlProfile called";
    bool accessGranted = false;
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    cppbor::Array pArray;
    pArray.add(id)
        .add(userAuthenticationRequired)
        .add(timeoutMillis)
        .add(secureUserId)
        .add(readerCertificate)
        .add(mac);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES response is not success";
        return {};
    }

    return true;
#else
    if (!eicPresentationValidateAccessControlProfile(&ctx_, id, readerCertificate.data(),
                                                     readerCertificate.size(),
                                                     userAuthenticationRequired, timeoutMillis,
                                                     secureUserId, mac.data(), &accessGranted)) {
        return {};
    }
#endif
    return accessGranted;
}

bool JCSecureHardwarePresentationProxy::startRetrieveEntries() {
    LOG(INFO) << "JCSecureHardwarePresentationProxy startRetrieveEntries called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_START_RETRIEVAL, 0, 0};

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_START_RETRIEVAL response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_START_RETRIEVAL response is not an array with one element";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_START_RETRIEVAL response is not success";
        return false;
    }

    return true;
#else
    return eicPresentationStartRetrieveEntries(&ctx_);
#endif
}

bool JCSecureHardwarePresentationProxy::calcMacKey(
        const vector<uint8_t>& sessionTranscript, const vector<uint8_t>& readerEphemeralPublicKey,
        const vector<uint8_t>& signingKeyBlob, const string& docType,
        unsigned int numNamespacesWithValues, size_t expectedProofOfProvisioningSize) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy calcMacKey called";
    if (signingKeyBlob.size() != 60) {
        eicDebug("Unexpected size %zd of signingKeyBlob, expected 60", signingKeyBlob.size());
        return false;
    }
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    cppbor::Array pArray;
    pArray.add(sessionTranscript)
        .add(readerEphemeralPublicKey)
        .add(signingKeyBlob)
        .add(docType)
        .add(numNamespacesWithValues)
        .add(expectedProofOfProvisioningSize);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_CAL_MAC_KEY, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return false;
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_CAL_MAC_KEY response is not valid CBOR: " << message;
        return false;
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 1) {
        LOG(ERROR) << "INS_ICS_CAL_MAC_KEY response is not an array with one element";
        return false;
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_CAL_MAC_KEY response is not success";
        return false;
    }

    return true;
#else
    return eicPresentationCalcMacKey(&ctx_, sessionTranscript.data(), sessionTranscript.size(),
                                     readerEphemeralPublicKey.data(), signingKeyBlob.data(),
                                     docType.c_str(), numNamespacesWithValues,
                                     expectedProofOfProvisioningSize);
#endif
}

AccessCheckResult JCSecureHardwarePresentationProxy::startRetrieveEntryValue(
        const string& nameSpace, const string& name, unsigned int newNamespaceNumEntries,
        int32_t entrySize, const vector<int32_t>& accessControlProfileIds) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy startRetrieveEntryValue called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION
#else
    uint8_t scratchSpace[512];
    EicAccessCheckResult result = eicPresentationStartRetrieveEntryValue(
            &ctx_, nameSpace.c_str(), name.c_str(), newNamespaceNumEntries, entrySize,
            accessControlProfileIds.data(), accessControlProfileIds.size(), scratchSpace,
            sizeof scratchSpace);
    switch (result) {
        case EIC_ACCESS_CHECK_RESULT_OK:
            return AccessCheckResult::kOk;
        case EIC_ACCESS_CHECK_RESULT_NO_ACCESS_CONTROL_PROFILES:
            return AccessCheckResult::kNoAccessControlProfiles;
        case EIC_ACCESS_CHECK_RESULT_FAILED:
            return AccessCheckResult::kFailed;
        case EIC_ACCESS_CHECK_RESULT_USER_AUTHENTICATION_FAILED:
            return AccessCheckResult::kUserAuthenticationFailed;
        case EIC_ACCESS_CHECK_RESULT_READER_AUTHENTICATION_FAILED:
            return AccessCheckResult::kReaderAuthenticationFailed;
    }
#endif
    eicDebug("Unknown result with code %d, returning kFailed", (int)result);
    return AccessCheckResult::kFailed;
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::retrieveEntryValue(
        const vector<uint8_t>& encryptedContent, const string& nameSpace, const string& name,
        const vector<int32_t>& accessControlProfileIds) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy retrieveEntryValue called";
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    return {};
#else
    uint8_t scratchSpace[512];
    vector<uint8_t> content;
    content.resize(encryptedContent.size() - 28);
    if (!eicPresentationRetrieveEntryValue(
                &ctx_, encryptedContent.data(), encryptedContent.size(), content.data(),
                nameSpace.c_str(), name.c_str(), accessControlProfileIds.data(),
                accessControlProfileIds.size(), scratchSpace, sizeof scratchSpace)) {
        return {};
    }
    return content;
#endif
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::finishRetrieval() {
    LOG(INFO) << "JCSecureHardwarePresentationProxy finishRetrieval called";
    vector<uint8_t> mac(32);
#ifdef ENABLE_JAVA_CARD_PRESENTATION
#else
    size_t macSize = 32;
    if (!eicPresentationFinishRetrieval(&ctx_, mac.data(), &macSize)) {
        return {};
    }
    mac.resize(macSize);
#endif
    return mac;
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::deleteCredential(
        const string& docType, const vector<uint8_t>& challenge, bool includeChallenge,
        size_t proofOfDeletionCborSize) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy deleteCredential called";
    vector<uint8_t> signatureOfToBeSigned(EIC_ECDSA_P256_SIGNATURE_SIZE);
#ifdef ENABLE_JAVA_CARD_PRESENTATION
#else
    if (!eicPresentationDeleteCredential(&ctx_, docType.c_str(), challenge.data(), challenge.size(),
                                         includeChallenge, proofOfDeletionCborSize,
                                         signatureOfToBeSigned.data())) {
        return {};
    }
#endif
    return signatureOfToBeSigned;
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::proveOwnership(
        const string& docType, bool testCredential, const vector<uint8_t>& challenge,
        size_t proofOfOwnershipCborSize) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy proveOwnership called";
    vector<uint8_t> signatureOfToBeSigned(EIC_ECDSA_P256_SIGNATURE_SIZE);
#ifdef ENABLE_JAVA_CARD_PRESENTATION
    cppbor::Array pArray;
    pArray.add(docType)
        .add(testCredential)
        .add(challenge)
        .add(proofOfOwnershipCborSize);
    vector<uint8_t> encodedCbor = pArray.encode();

    CommandApdu command{AppletConnection::CLA_PROPRIETARY, AppletConnection::INS_ICS_PROVE_OWNERSHIP, 0, 0, encodedCbor.size(), 0};
    std::copy(encodedCbor.begin(), encodedCbor.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return {};
    }
    vector<uint8_t> responseCbor(response.dataSize());
    std::copy(response.dataBegin(), response.dataEnd(), responseCbor.begin());
    auto [item, _, message] = cppbor::parse(responseCbor);
    if (item == nullptr) {
        LOG(ERROR) << "INS_ICS_PROVE_OWNERSHIP response is not valid CBOR: " << message;
        return {};
    }

    const cppbor::Array* arrayItem = item->asArray();
    if (arrayItem == nullptr || arrayItem->size() != 2) {
        LOG(ERROR) << "INS_ICS_PROVE_OWNERSHIP response is not an array with two elements";
        return {};
    }

    const cppbor::Uint* successCode = (*arrayItem)[0]->asUint();
    if(successCode->value() != 0) {
        LOG(ERROR) << "INS_ICS_PROVE_OWNERSHIP response is not success";
        return {};
    }

    const cppbor::Array* returnArray = (*arrayItem)[1]->asArray();
    const cppbor::Bstr* signatureOfToBeSignedBstr = (*returnArray)[0]->asBstr();
    const vector<uint8_t> derSignature = signatureOfToBeSignedBstr->value();

    ECDSA_SIG* sig;
    const unsigned char* p = derSignature.data();
    sig = d2i_ECDSA_SIG(nullptr, &p, derSignature.size());
    if (sig == nullptr) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES Error decoding DER signature";
        return {};
    }

    if (BN_bn2binpad(sig->r, signatureOfToBeSigned.data(), 32) != 32) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES Error encoding r";
        return {};
    }
    if (BN_bn2binpad(sig->s, signatureOfToBeSigned.data() + 32, 32) != 32) {
        LOG(ERROR) << "INS_ICS_FINISH_ADDING_ENTRIES Error encoding s";
        return {};
    }
#else
    if (!eicPresentationProveOwnership(&ctx_, docType.c_str(), testCredential, challenge.data(),
                                       challenge.size(), proofOfOwnershipCborSize,
                                       signatureOfToBeSigned.data())) {
        return {};
    }
#endif
    return signatureOfToBeSigned;
}

}  // namespace android::hardware::identity
