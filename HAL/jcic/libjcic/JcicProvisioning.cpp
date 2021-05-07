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

#define LOG_TAG "JcicProvisioning"

#include <vector>
#include <android-base/logging.h>
#include "JcicProvisioning.h"
#include "TransportUtil.h"

using ::std::vector;
namespace android::hardware::identity {

bool jcicProvisioningInit(JcicProvisioning* ctx, bool testCredential) {
    LOG(ERROR) << "jcicProvisioningInit called";
    vector<uint8_t> cborData;
    vector<uint8_t> input;
    uint8_t p1 = 0x00;
    uint8_t p2 = 0x00;
    se_transport::TransportUtil::sendData(se_transport::Instruction::INS_ICS_CREATE_CREDENTIAL, input, p1, p2, cborData);
    return false;
}

bool jcicProvisioningInitForUpdate(JcicProvisioning* ctx, bool testCredential, const char* docType,
                                  const uint8_t* encryptedCredentialKeys,
                                  size_t encryptedCredentialKeysSize) {

    return true;
}

bool jcicProvisioningCreateCredentialKey(JcicProvisioning* ctx, const uint8_t* challenge,
                                        size_t challengeSize, const uint8_t* applicationId,
                                        size_t applicationIdSize, uint8_t* publicKeyCert,
                                        size_t* publicKeyCertSize) {

    return true;
}

bool jcicProvisioningStartPersonalization(JcicProvisioning* ctx, int accessControlProfileCount,
                                         const int* entryCounts, size_t numEntryCounts,
                                         const char* docType,
                                         size_t expectedProofOfProvisioningSize) {

    return true;
}

bool jcicProvisioningAddAccessControlProfile(JcicProvisioning* ctx, int id,
                                            const uint8_t* readerCertificate,
                                            size_t readerCertificateSize,
                                            bool userAuthenticationRequired, uint64_t timeoutMillis,
                                            uint64_t secureUserId, uint8_t outMac[28]) {

    return true;
}

bool jcicProvisioningBeginAddEntry(JcicProvisioning* ctx, const int* accessControlProfileIds,
                                  size_t numAccessControlProfileIds, const char* nameSpace,
                                  const char* name, uint64_t entrySize, uint8_t* scratchSpace,
                                  size_t scratchSpaceSize) {

    return true;
}

bool jcicProvisioningAddEntryValue(JcicProvisioning* ctx, const int* accessControlProfileIds,
                                  size_t numAccessControlProfileIds, const char* nameSpace,
                                  const char* name, const uint8_t* content, size_t contentSize,
                                  uint8_t* outEncryptedContent, uint8_t* scratchSpace,
                                  size_t scratchSpaceSize) {

    return true;
}

bool jcicProvisioningFinishAddingEntries(
        JcicProvisioning* ctx, uint8_t signatureOfToBeSigned[JCIC_ECDSA_P256_SIGNATURE_SIZE]) {

    return true;
}

bool jcicProvisioningFinishGetCredentialData(JcicProvisioning* ctx, const char* docType,
                                            uint8_t* encryptedCredentialKeys,
                                            size_t* encryptedCredentialKeysSize) {


    return true;
}

} //namespace android::hardware::identity
