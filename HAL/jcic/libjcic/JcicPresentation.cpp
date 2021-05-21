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

#include "JcicPresentation.h"

#include <inttypes.h>
namespace android::hardware::identity {

bool jcicPresentationInit(JcicPresentation* ctx, bool testCredential, const char* docType,
                         const uint8_t* encryptedCredentialKeys,
                         size_t encryptedCredentialKeysSize) {

    return true;
}

bool jcicPresentationGenerateSigningKeyPair(JcicPresentation* ctx, const char* docType, time_t now,
                                           uint8_t* publicKeyCert, size_t* publicKeyCertSize,
                                           uint8_t signingKeyBlob[60]) {


    return true;
}

bool jcicPresentationCreateEphemeralKeyPair(JcicPresentation* ctx,
                                           uint8_t ephemeralPrivateKey[JCIC_P256_PRIV_KEY_SIZE]) {

    return true;
}

bool jcicPresentationCreateAuthChallenge(JcicPresentation* ctx, uint64_t* authChallenge) {

    return true;
}

// From "COSE Algorithms" registry
//
#define COSE_ALG_ECDSA_256 -7

bool jcicPresentationValidateRequestMessage(JcicPresentation* ctx, const uint8_t* sessionTranscript,
                                           size_t sessionTranscriptSize,
                                           const uint8_t* requestMessage, size_t requestMessageSize,
                                           int coseSignAlg,
                                           const uint8_t* readerSignatureOfToBeSigned,
                                           size_t readerSignatureOfToBeSignedSize) {

    return true;
}

// Validates the next certificate in the reader certificate chain.
bool jcicPresentationPushReaderCert(JcicPresentation* ctx, const uint8_t* certX509,
                                   size_t certX509Size) {

    return true;
}

bool jcicPresentationSetAuthToken(JcicPresentation* ctx, uint64_t challenge, uint64_t secureUserId,
                                 uint64_t authenticatorId, int hardwareAuthenticatorType,
                                 uint64_t timeStamp, const uint8_t* mac, size_t macSize,
                                 uint64_t verificationTokenChallenge,
                                 uint64_t verificationTokenTimestamp,
                                 int verificationTokenSecurityLevel,
                                 const uint8_t* verificationTokenMac,
                                 size_t verificationTokenMacSize) {

    return true;
}

static bool checkUserAuth(JcicPresentation* ctx, bool userAuthenticationRequired, int timeoutMillis,
                          uint64_t secureUserId) {


    return true;
}

static bool checkReaderAuth(JcicPresentation* ctx, const uint8_t* readerCertificate,
                            size_t readerCertificateSize) {

    return true;
}

// Note: This function returns false _only_ if an error occurred check for access, _not_
// whether access is granted. Whether access is granted is returned in |accessGranted|.
//
bool jcicPresentationValidateAccessControlProfile(JcicPresentation* ctx, int id,
                                                 const uint8_t* readerCertificate,
                                                 size_t readerCertificateSize,
                                                 bool userAuthenticationRequired, int timeoutMillis,
                                                 uint64_t secureUserId, const uint8_t mac[28],
                                                 bool* accessGranted) {

    return true;
}

bool jcicPresentationCalcMacKey(JcicPresentation* ctx, const uint8_t* sessionTranscript,
                               size_t sessionTranscriptSize,
                               const uint8_t readerEphemeralPublicKey[JCIC_P256_PUB_KEY_SIZE],
                               const uint8_t signingKeyBlob[60], const char* docType,
                               unsigned int numNamespacesWithValues,
                               size_t expectedDeviceNamespacesSize) {

    return true;
}

bool jcicPresentationStartRetrieveEntries(JcicPresentation* ctx) {

    return true;
}

JcicAccessCheckResult jcicPresentationStartRetrieveEntryValue(
        JcicPresentation* ctx, const char* nameSpace, const char* name,
        unsigned int newNamespaceNumEntries, int32_t /* entrySize */,
        const int* accessControlProfileIds, size_t numAccessControlProfileIds,
        uint8_t* scratchSpace, size_t scratchSpaceSize) {
    JcicAccessCheckResult result = JCIC_ACCESS_CHECK_RESULT_FAILED;
    return result;
}

// Note: |content| must be big enough to hold |encryptedContentSize| - 28 bytes.
bool jcicPresentationRetrieveEntryValue(JcicPresentation* ctx, const uint8_t* encryptedContent,
                                       size_t encryptedContentSize, uint8_t* content,
                                       const char* nameSpace, const char* name,
                                       const int* accessControlProfileIds,
                                       size_t numAccessControlProfileIds, uint8_t* scratchSpace,
                                       size_t scratchSpaceSize) {


    return true;
}

bool jcicPresentationFinishRetrieval(JcicPresentation* ctx, uint8_t* digestToBeMaced,
                                    size_t* digestToBeMacedSize) {

    return true;
}

bool jcicPresentationDeleteCredential(JcicPresentation* ctx, const char* docType,
                                     const uint8_t* challenge, size_t challengeSize,
                                     bool includeChallenge, size_t proofOfDeletionCborSize,
                                     uint8_t signatureOfToBeSigned[JCIC_ECDSA_P256_SIGNATURE_SIZE]) {

    return true;
}

bool jcicPresentationProveOwnership(JcicPresentation* ctx, const char* docType, bool testCredential,
                                   const uint8_t* challenge, size_t challengeSize,
                                   size_t proofOfOwnershipCborSize,
                                   uint8_t signatureOfToBeSigned[JCIC_ECDSA_P256_SIGNATURE_SIZE]) {

    return true;
}

} //namespace android::hardware::identity