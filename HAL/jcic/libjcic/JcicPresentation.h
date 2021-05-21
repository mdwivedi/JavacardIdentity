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

#ifndef ANDROID_HARDWARE_IDENTITY_JCIC_PRESENTATION_H
#define ANDROID_HARDWARE_IDENTITY_JCIC_PRESENTATION_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

namespace android::hardware::identity {

// The maximum size we support for public keys in reader certificates.
#define JCIC_PRESENTATION_MAX_READER_PUBLIC_KEY_SIZE 65

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
    int featureLevel;

    uint8_t storageKey[JCIC_AES_128_KEY_SIZE];
    uint8_t credentialPrivateKey[JCIC_P256_PRIV_KEY_SIZE];

    uint8_t ephemeralPrivateKey[JCIC_P256_PRIV_KEY_SIZE];

    // The challenge generated with jcicPresentationCreateAuthChallenge()
    uint64_t authChallenge;

    // Set by jcicPresentationSetAuthToken() and contains the fields
    // from the passed in authToken and verificationToken.
    //
    uint64_t authTokenChallenge;
    uint64_t authTokenSecureUserId;
    uint64_t authTokenTimestamp;
    uint64_t verificationTokenTimestamp;

    // The public key for the reader.
    //
    // (During the process of pushing reader certificates, this is also used to store
    // the public key of the previously pushed certificate.)
    //
    uint8_t readerPublicKey[JCIC_PRESENTATION_MAX_READER_PUBLIC_KEY_SIZE];
    size_t readerPublicKeySize;

    // This is set to true only if jcicPresentationValidateRequestMessage() successfully
    // validated the requestMessage.
    //
    // Why even record this? Because there's no requirement the HAL actually calls that
    // function and we validate ACPs before it's called... so it's possible that a
    // compromised HAL could trick us into marking ACPs as authorized while they in fact
    // aren't.
    bool requestMessageValidated;
    bool buildCbor;

    // Set to true initialized as a test credential.
    bool testCredential;

    // These are bitmasks indicating which of the possible 32 access control profiles are
    // authorized. They are built up by jcicPresentationValidateAccessControlProfile().
    //
    uint32_t accessControlProfileMaskValidated;         // True if the profile was validated.
    uint32_t accessControlProfileMaskUsesReaderAuth;    // True if the ACP is using reader auth
    uint32_t accessControlProfileMaskFailedReaderAuth;  // True if failed reader auth
    uint32_t accessControlProfileMaskFailedUserAuth;    // True if failed user auth

    // SHA-256 for AdditionalData, updated for each entry.
    uint8_t additionalDataSha256[JCIC_SHA256_DIGEST_SIZE];

    // SHA-256 of ProofOfProvisioning. Set to NUL-bytes or initialized from CredentialKeys data
    // if credential was created with feature version 202101 or later.
    uint8_t proofOfProvisioningSha256[JCIC_SHA256_DIGEST_SIZE];

    size_t expectedCborSizeAtEnd;
} JcicPresentation;

bool jcicPresentationInit(JcicPresentation* ctx, bool testCredential, const char* docType,
                         const uint8_t* encryptedCredentialKeys,
                         size_t encryptedCredentialKeysSize);

bool jcicPresentationGenerateSigningKeyPair(JcicPresentation* ctx, const char* docType, time_t now,
                                           uint8_t* publicKeyCert, size_t* publicKeyCertSize,
                                           uint8_t signingKeyBlob[60]);

// Create an ephemeral key-pair.
//
// The private key is stored in |ctx->ephemeralPrivateKey| and also returned in
// |ephemeralPrivateKey|.
//
bool jcicPresentationCreateEphemeralKeyPair(JcicPresentation* ctx,
                                           uint8_t ephemeralPrivateKey[JCIC_P256_PRIV_KEY_SIZE]);

// Returns a non-zero challenge in |authChallenge|.
bool jcicPresentationCreateAuthChallenge(JcicPresentation* ctx, uint64_t* authChallenge);

// Starts retrieveing entries.
//
bool jcicPresentationStartRetrieveEntries(JcicPresentation* ctx);

// Sets the auth-token.
bool jcicPresentationSetAuthToken(JcicPresentation* ctx, uint64_t challenge, uint64_t secureUserId,
                                 uint64_t authenticatorId, int hardwareAuthenticatorType,
                                 uint64_t timeStamp, const uint8_t* mac, size_t macSize,
                                 uint64_t verificationTokenChallenge,
                                 uint64_t verificationTokenTimeStamp,
                                 int verificationTokenSecurityLevel,
                                 const uint8_t* verificationTokenMac,
                                 size_t verificationTokenMacSize);

// Function to push certificates in the reader certificate chain.
//
// This should start with the root certificate (e.g. the last in the chain) and
// continue up the chain, ending with the certificate for the reader.
//
// Calls to this function should be interleaved with calls to the
// jcicPresentationValidateAccessControlProfile() function, see below.
//
bool jcicPresentationPushReaderCert(JcicPresentation* ctx, const uint8_t* certX509,
                                   size_t certX509Size);

// Checks an access control profile.
//
// Returns false if an error occurred while checking the profile (e.g. MAC doesn't check out).
//
// Returns in |accessGranted| whether access is granted.
//
// If |readerCertificate| is non-empty and the public key of one of those
// certificates appear in the chain presented by the reader, this function must
// be called after pushing that certificate using
// jcicPresentationPushReaderCert().
//
bool jcicPresentationValidateAccessControlProfile(JcicPresentation* ctx, int id,
                                                 const uint8_t* readerCertificate,
                                                 size_t readerCertificateSize,
                                                 bool userAuthenticationRequired, int timeoutMillis,
                                                 uint64_t secureUserId, const uint8_t mac[28],
                                                 bool* accessGranted);

// Validates that the given requestMessage is signed by the public key in the
// certificate last set with jcicPresentationPushReaderCert().
//
// The format of the signature is the same encoding as the 'signature' field of
// COSE_Sign1 - that is, it's the R and S integers both with the same length as
// the key-size.
//
// Must be called after jcicPresentationPushReaderCert() have been used to push
// the final certificate. Which is the certificate of the reader itself.
//
bool jcicPresentationValidateRequestMessage(JcicPresentation* ctx, const uint8_t* sessionTranscript,
                                           size_t sessionTranscriptSize,
                                           const uint8_t* requestMessage, size_t requestMessageSize,
                                           int coseSignAlg,
                                           const uint8_t* readerSignatureOfToBeSigned,
                                           size_t readerSignatureOfToBeSignedSize);

typedef enum {
    // Returned if access is granted.
    JCIC_ACCESS_CHECK_RESULT_OK,

    // Returned if an error occurred checking for access.
    JCIC_ACCESS_CHECK_RESULT_FAILED,

    // Returned if access was denied because item is configured without any
    // access control profiles.
    JCIC_ACCESS_CHECK_RESULT_NO_ACCESS_CONTROL_PROFILES,

    // Returned if access was denied because of user authentication.
    JCIC_ACCESS_CHECK_RESULT_USER_AUTHENTICATION_FAILED,

    // Returned if access was denied because of reader authentication.
    JCIC_ACCESS_CHECK_RESULT_READER_AUTHENTICATION_FAILED,
} JcicAccessCheckResult;

// Passes enough information to calculate the MACing key
//
bool jcicPresentationCalcMacKey(JcicPresentation* ctx, const uint8_t* sessionTranscript,
                               size_t sessionTranscriptSize,
                               const uint8_t readerEphemeralPublicKey[JCIC_P256_PUB_KEY_SIZE],
                               const uint8_t signingKeyBlob[60], const char* docType,
                               unsigned int numNamespacesWithValues,
                               size_t expectedDeviceNamespacesSize);

// The scratchSpace should be set to a buffer at least 512 bytes (ideally 1024
// bytes, the bigger the better). It's done this way to avoid allocating stack
// space.
//
JcicAccessCheckResult jcicPresentationStartRetrieveEntryValue(
        JcicPresentation* ctx, const char* nameSpace, const char* name,
        unsigned int newNamespaceNumEntries, int32_t entrySize, const int* accessControlProfileIds,
        size_t numAccessControlProfileIds, uint8_t* scratchSpace, size_t scratchSpaceSize);

// Note: |content| must be big enough to hold |encryptedContentSize| - 28 bytes.
//
// The scratchSpace should be set to a buffer at least 512 bytes. It's done this way to
// avoid allocating stack space.
//
bool jcicPresentationRetrieveEntryValue(JcicPresentation* ctx, const uint8_t* encryptedContent,
                                       size_t encryptedContentSize, uint8_t* content,
                                       const char* nameSpace, const char* name,
                                       const int* accessControlProfileIds,
                                       size_t numAccessControlProfileIds, uint8_t* scratchSpace,
                                       size_t scratchSpaceSize);

// Returns the HMAC-SHA256 of |ToBeMaced| as per RFC 8051 "6.3. How to Compute
// and Verify a MAC".
bool jcicPresentationFinishRetrieval(JcicPresentation* ctx, uint8_t* digestToBeMaced,
                                    size_t* digestToBeMacedSize);

// The data returned in |signatureOfToBeSigned| contains the ECDSA signature of
// the ToBeSigned CBOR from RFC 8051 "4.4. Signing and Verification Process"
// where content is set to the ProofOfDeletion CBOR.
//
bool jcicPresentationDeleteCredential(JcicPresentation* ctx, const char* docType,
                                     const uint8_t* challenge, size_t challengeSize,
                                     bool includeChallenge, size_t proofOfDeletionCborSize,
                                     uint8_t signatureOfToBeSigned[JCIC_ECDSA_P256_SIGNATURE_SIZE]);

// The data returned in |signatureOfToBeSigned| contains the ECDSA signature of
// the ToBeSigned CBOR from RFC 8051 "4.4. Signing and Verification Process"
// where content is set to the ProofOfOwnership CBOR.
//
bool jcicPresentationProveOwnership(JcicPresentation* ctx, const char* docType, bool testCredential,
                                   const uint8_t* challenge, size_t challengeSize,
                                   size_t proofOfOwnershipCborSize,
                                   uint8_t signatureOfToBeSigned[JCIC_ECDSA_P256_SIGNATURE_SIZE]);

} //namespace android::hardware::identity
#endif  // ANDROID_HARDWARE_IDENTITY_JCIC_PRESENTATION_H
