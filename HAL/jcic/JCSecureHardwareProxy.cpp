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
#define ENABLE_JAVA_CARD 1

#include <android/hardware/identity/support/IdentityCredentialSupport.h>

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

#ifdef ENABLE_JAVA_CARD
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>
#include "AppletConnection.h"
#else
#include <libeic.h>
#endif

#include "JCSecureHardwareProxy.h"

using ::std::optional;
using ::std::string;
using ::std::tuple;
using ::std::vector;

namespace android::hardware::identity {
// ----------------------------------------------------------------------

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

JCSecureHardwareProvisioningProxy::~JCSecureHardwareProvisioningProxy() {}

bool JCSecureHardwareProvisioningProxy::shutdown() {
    LOG(INFO) << "JCSecureHardwareProvisioningProxy shutdown";
    mAppletConnection.close();
    return true;
}

bool JCSecureHardwareProvisioningProxy::initialize(bool testCredential) {
    LOG(INFO) << "JCSecureHardwareProvisioningProxy created, sizeof(EicProvisioning): "
              << sizeof(EicProvisioning);
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
#ifdef ENABLE_JAVA_CARD
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
#ifdef ENABLE_JAVA_CARD

    if (!mAppletConnection.connectToTransportClient()) {
        return {};
    }

    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return {};
        }
    }

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

    optional<vector<vector<uint8_t>>> certChain =  android::hardware::identity::support::createAttestationForEcPublicKey(
                    pubKey, challenge, applicationId);
    // Extract certificate chain.
    vector<uint8_t> pubKeyCert =
            android::hardware::identity::support::certificateChainJoin(certChain.value());

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

#ifdef ENABLE_JAVA_CARD
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

#ifdef ENABLE_JAVA_CARD
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
#ifdef ENABLE_JAVA_CARD
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
#ifdef ENABLE_JAVA_CARD
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
#ifdef ENABLE_JAVA_CARD
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
#ifdef ENABLE_JAVA_CARD
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

JCSecureHardwarePresentationProxy::~JCSecureHardwarePresentationProxy() {}

bool JCSecureHardwarePresentationProxy::initialize(bool testCredential, string docType,
                                                     vector<uint8_t> encryptedCredentialKeys) {
    LOG(INFO) << "JCSecureHardwarePresentationProxy created, sizeof(EicPresentation): "
              << sizeof(EicPresentation);
    return eicPresentationInit(&ctx_, testCredential, docType.c_str(),
                               encryptedCredentialKeys.data(), encryptedCredentialKeys.size());
}

// Returns publicKeyCert (1st component) and signingKeyBlob (2nd component)
optional<pair<vector<uint8_t>, vector<uint8_t>>>
JCSecureHardwarePresentationProxy::generateSigningKeyPair(string docType, time_t now) {
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
}

// Returns private key
optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::createEphemeralKeyPair() {
    vector<uint8_t> priv(EIC_P256_PRIV_KEY_SIZE);
    if (!eicPresentationCreateEphemeralKeyPair(&ctx_, priv.data())) {
        return {};
    }
    return priv;
}

optional<uint64_t> JCSecureHardwarePresentationProxy::createAuthChallenge() {
    uint64_t challenge;
    if (!eicPresentationCreateAuthChallenge(&ctx_, &challenge)) {
        return {};
    }
    return challenge;
}

bool JCSecureHardwarePresentationProxy::shutdown() {
    LOG(INFO) << "JCSecureHardwarePresentationProxy shutdown";
    return true;
}

bool JCSecureHardwarePresentationProxy::pushReaderCert(const vector<uint8_t>& certX509) {
    return eicPresentationPushReaderCert(&ctx_, certX509.data(), certX509.size());
}

bool JCSecureHardwarePresentationProxy::validateRequestMessage(
        const vector<uint8_t>& sessionTranscript, const vector<uint8_t>& requestMessage,
        int coseSignAlg, const vector<uint8_t>& readerSignatureOfToBeSigned) {
    return eicPresentationValidateRequestMessage(
            &ctx_, sessionTranscript.data(), sessionTranscript.size(), requestMessage.data(),
            requestMessage.size(), coseSignAlg, readerSignatureOfToBeSigned.data(),
            readerSignatureOfToBeSigned.size());
}

bool JCSecureHardwarePresentationProxy::setAuthToken(
        uint64_t challenge, uint64_t secureUserId, uint64_t authenticatorId,
        int hardwareAuthenticatorType, uint64_t timeStamp, const vector<uint8_t>& mac,
        uint64_t verificationTokenChallenge, uint64_t verificationTokenTimestamp,
        int verificationTokenSecurityLevel, const vector<uint8_t>& verificationTokenMac) {
    return eicPresentationSetAuthToken(&ctx_, challenge, secureUserId, authenticatorId,
                                       hardwareAuthenticatorType, timeStamp, mac.data(), mac.size(),
                                       verificationTokenChallenge, verificationTokenTimestamp,
                                       verificationTokenSecurityLevel, verificationTokenMac.data(),
                                       verificationTokenMac.size());
}

optional<bool> JCSecureHardwarePresentationProxy::validateAccessControlProfile(
        int id, const vector<uint8_t>& readerCertificate, bool userAuthenticationRequired,
        int timeoutMillis, uint64_t secureUserId, const vector<uint8_t>& mac) {
    bool accessGranted = false;
    if (!eicPresentationValidateAccessControlProfile(&ctx_, id, readerCertificate.data(),
                                                     readerCertificate.size(),
                                                     userAuthenticationRequired, timeoutMillis,
                                                     secureUserId, mac.data(), &accessGranted)) {
        return {};
    }
    return accessGranted;
}

bool JCSecureHardwarePresentationProxy::startRetrieveEntries() {
    return eicPresentationStartRetrieveEntries(&ctx_);
}

bool JCSecureHardwarePresentationProxy::calcMacKey(
        const vector<uint8_t>& sessionTranscript, const vector<uint8_t>& readerEphemeralPublicKey,
        const vector<uint8_t>& signingKeyBlob, const string& docType,
        unsigned int numNamespacesWithValues, size_t expectedProofOfProvisioningSize) {
    if (signingKeyBlob.size() != 60) {
        eicDebug("Unexpected size %zd of signingKeyBlob, expected 60", signingKeyBlob.size());
        return false;
    }
    return eicPresentationCalcMacKey(&ctx_, sessionTranscript.data(), sessionTranscript.size(),
                                     readerEphemeralPublicKey.data(), signingKeyBlob.data(),
                                     docType.c_str(), numNamespacesWithValues,
                                     expectedProofOfProvisioningSize);
}

AccessCheckResult JCSecureHardwarePresentationProxy::startRetrieveEntryValue(
        const string& nameSpace, const string& name, unsigned int newNamespaceNumEntries,
        int32_t entrySize, const vector<int32_t>& accessControlProfileIds) {
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
    eicDebug("Unknown result with code %d, returning kFailed", (int)result);
    return AccessCheckResult::kFailed;
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::retrieveEntryValue(
        const vector<uint8_t>& encryptedContent, const string& nameSpace, const string& name,
        const vector<int32_t>& accessControlProfileIds) {
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
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::finishRetrieval() {
    vector<uint8_t> mac(32);
    size_t macSize = 32;
    if (!eicPresentationFinishRetrieval(&ctx_, mac.data(), &macSize)) {
        return {};
    }
    mac.resize(macSize);
    return mac;
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::deleteCredential(
        const string& docType, const vector<uint8_t>& challenge, bool includeChallenge,
        size_t proofOfDeletionCborSize) {
    vector<uint8_t> signatureOfToBeSigned(EIC_ECDSA_P256_SIGNATURE_SIZE);
    if (!eicPresentationDeleteCredential(&ctx_, docType.c_str(), challenge.data(), challenge.size(),
                                         includeChallenge, proofOfDeletionCborSize,
                                         signatureOfToBeSigned.data())) {
        return {};
    }
    return signatureOfToBeSigned;
}

optional<vector<uint8_t>> JCSecureHardwarePresentationProxy::proveOwnership(
        const string& docType, bool testCredential, const vector<uint8_t>& challenge,
        size_t proofOfOwnershipCborSize) {
    vector<uint8_t> signatureOfToBeSigned(EIC_ECDSA_P256_SIGNATURE_SIZE);
    if (!eicPresentationProveOwnership(&ctx_, docType.c_str(), testCredential, challenge.data(),
                                       challenge.size(), proofOfOwnershipCborSize,
                                       signatureOfToBeSigned.data())) {
        return {};
    }
    return signatureOfToBeSigned;
}

}  // namespace android::hardware::identity
