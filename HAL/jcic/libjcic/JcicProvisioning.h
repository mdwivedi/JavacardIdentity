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

#if !defined(JCIC_INSIDE_LIBJCIC_H) && !defined(JCIC_COMPILATION)
#error "Never include this file directly, include libjcic.h instead."
#endif

#ifndef ANDROID_HARDWARE_IDENTITY_JCIC_PROVISIONING_H
#define ANDROID_HARDWARE_IDENTITY_JCIC_PROVISIONING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

namespace android::hardware::identity {

#define JCIC_MAX_NUM_NAMESPACES 32
#define JCIC_MAX_NUM_ACCESS_CONTROL_PROFILE_IDS 32

#define JCIC_SHA256_DIGEST_SIZE 32

// The size of a P-256 private key.
//
#define JCIC_P256_PRIV_KEY_SIZE 32

// The size of a P-256 public key in uncompressed form.
//
// The public key is stored in uncompressed form, first the X coordinate, then
// the Y coordinate.
//
#define JCIC_P256_PUB_KEY_SIZE 64

// Size of one of the coordinates in a curve-point.
//
#define JCIC_P256_COORDINATE_SIZE 32

// The size of an ECSDA signature using P-256.
//
// The R and S values are stored here, first R then S.
//
#define JCIC_ECDSA_P256_SIGNATURE_SIZE 64

#define JCIC_AES_128_KEY_SIZE 16

typedef struct {
    // Set by jcicCreateCredentialKey() OR jcicProvisioningInitForUpdate()
    uint8_t credentialPrivateKey[JCIC_P256_PRIV_KEY_SIZE];

    int numEntryCounts;
    uint8_t entryCounts[JCIC_MAX_NUM_NAMESPACES];

    int curNamespace;
    int curNamespaceNumProcessed;

    size_t curEntrySize;
    size_t curEntryNumBytesReceived;

    // Set by jcicProvisioningInit() OR jcicProvisioningInitForUpdate()
    uint8_t storageKey[JCIC_AES_128_KEY_SIZE];

    size_t expectedCborSizeAtEnd;

    // SHA-256 for AdditionalData, updated for each entry.
    uint8_t additionalDataSha256[JCIC_SHA256_DIGEST_SIZE];

    bool testCredential;

    // Set to true if this is an update.
    bool isUpdate;
} JcicProvisioning;

bool jcicProvisioningInit(JcicProvisioning* ctx, bool testCredential);

bool jcicProvisioningInitForUpdate(JcicProvisioning* ctx, bool testCredential, const char* docType,
                                  const uint8_t* encryptedCredentialKeys,
                                  size_t encryptedCredentialKeysSize);

bool jcicProvisioningCreateCredentialKey(JcicProvisioning* ctx, const uint8_t* challenge,
                                        size_t challengeSize, const uint8_t* applicationId,
                                        size_t applicationIdSize, uint8_t* publicKeyCert,
                                        size_t* publicKeyCertSize);

bool jcicProvisioningStartPersonalization(JcicProvisioning* ctx, int accessControlProfileCount,
                                         const int* entryCounts, size_t numEntryCounts,
                                         const char* docType,
                                         size_t expectedProofOfProvisioningingSize);

bool jcicProvisioningAddAccessControlProfile(JcicProvisioning* ctx, int id,
                                            const uint8_t* readerCertificate,
                                            size_t readerCertificateSize,
                                            bool userAuthenticationRequired, uint64_t timeoutMillis,
                                            uint64_t secureUserId, uint8_t outMac[28]);

// The scratchSpace should be set to a buffer at least 512 bytes. It's done this way to
// avoid allocating stack space.
//
bool jcicProvisioningBeginAddEntry(JcicProvisioning* ctx, const int* accessControlProfileIds,
                                  size_t numAccessControlProfileIds, const char* nameSpace,
                                  const char* name, uint64_t entrySize, uint8_t* scratchSpace,
                                  size_t scratchSpaceSize);

// The outEncryptedContent array must be contentSize + 28 bytes long.
//
// The scratchSpace should be set to a buffer at least 512 bytes. It's done this way to
// avoid allocating stack space.
//
bool jcicProvisioningAddEntryValue(JcicProvisioning* ctx, const int* accessControlProfileIds,
                                  size_t numAccessControlProfileIds, const char* nameSpace,
                                  const char* name, const uint8_t* content, size_t contentSize,
                                  uint8_t* outEncryptedContent, uint8_t* scratchSpace,
                                  size_t scratchSpaceSize);

// The data returned in |signatureOfToBeSigned| contains the ECDSA signature of
// the ToBeSigned CBOR from RFC 8051 "4.4. Signing and Verification Process"
// where content is set to the ProofOfProvisioninging CBOR.
//
bool jcicProvisioningFinishAddingEntries(
        JcicProvisioning* ctx, uint8_t signatureOfToBeSigned[JCIC_ECDSA_P256_SIGNATURE_SIZE]);

//
//
// The |encryptedCredentialKeys| array is set to AES-GCM-ENC(HBK, R, CredentialKeys, docType)
// where
//
//   CredentialKeys = [
//     bstr,   ; storageKey, a 128-bit AES key
//     bstr    ; credentialPrivKey, the private key for credentialKey
//     bstr    ; SHA-256(ProofOfProvisioning)
//   ]
//
// for feature version 202101. For feature version 202009 the third field was not present.
//
// Since |storageKey| is 16 bytes and |credentialPrivKey| is 32 bytes, the
// encoded CBOR for CredentialKeys is 86 bytes and consequently
// |encryptedCredentialKeys| will be no longer than 86 + 28 = 114 bytes.
//
bool jcicProvisioningFinishGetCredentialData(JcicProvisioning* ctx, const char* docType,
                                            uint8_t* encryptedCredentialKeys,
                                            size_t* encryptedCredentialKeysSize);

} //namespace android::hardware::identity

#endif  // ANDROID_HARDWARE_IDENTITY_JCIC_PROVISIONING_H
