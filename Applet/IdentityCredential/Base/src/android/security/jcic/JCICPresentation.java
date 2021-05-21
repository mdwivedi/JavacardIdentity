package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

import static android.security.jcic.ICConstants.*;
import static android.security.jcic.ICConstants.LONG_SIZE;

final class JCICPresentation {

	private CryptoManager mCryptoManager;

    // Reference to the internal APDU manager instance
    private final APDUManager mAPDUManager;
    
    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;

    private final byte[] mProofOfProvisioningSha256;

	private final byte[] mEphemeralPrivateKey;

	private final byte[] mReaderPublicKey;
	private final short[] mReaderPublicKeySize;

    private final short[] mKeyPairLengthsHolder;

    private final byte[] mAuthChallenge;

	private final MessageDigest mDigest;
	private final HMACKey mHmacKey;
	private final Signature mHmacSignature;

	// This is set to true only if eicPresentationValidateRequestMessage() successfully
	// validated the requestMessage.
	//
	// Why even record this? Because there's no requirement the HAL actually calls that
	// function and we validate ACPs before it's called... so it's possible that a
	// compromised HAL could trick us into marking ACPs as authorized while they in fact
	// aren't.
	byte mRequestMessageValidated = (byte)0;
	byte mBuildCbor = (byte)1;
	private final boolean[] mStatus;

	// These are bitmasks indicating which of the possible 32 access control profiles are
	// authorized. They are built up by eicPresentationValidateAccessControlProfile().
	//
	private final byte mAccessControlProfileMaskValidatedOffset = (byte) 0;
	private final byte mAccessControlProfileMaskUsesReaderAuthOffset = (byte)(mAccessControlProfileMaskValidatedOffset + INT_SIZE);
	private final byte mAccessControlProfileMaskFailedReaderAuthOffset = (byte)(mAccessControlProfileMaskUsesReaderAuthOffset + INT_SIZE);
	private final byte mAccessControlProfileMaskFailedUserAuthOffset = (byte)(mAccessControlProfileMaskFailedReaderAuthOffset + INT_SIZE);
	private final byte[] mAcpMasksInts;

	// Set by eicPresentationSetAuthToken() and contains the fields
	// from the passed in authToken and verificationToken.
	//
	byte mAuthChallengeOffset = (byte) 0;
	byte mAuthTokenChallengeOffset = (byte) (mAuthChallengeOffset + LONG_SIZE);
	byte mAuthTokenSecureUserIdOffset = (byte)(mAuthTokenChallengeOffset + LONG_SIZE);
	byte mAuthTokenTimestampOffset = (byte)(mAuthTokenSecureUserIdOffset + LONG_SIZE);
	byte mVerificationTokenTimestampOffset = (byte)(mAuthTokenTimestampOffset + LONG_SIZE);
	private final byte[] mAuthAndVerificationTokensLongs;

	private final byte[] mIntExpectedCborSizeAtEnd;
	private final byte[] mIntCurrentCborSize;

	public JCICPresentation(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
		mProofOfProvisioningSha256 = JCSystem.makeTransientByteArray(CryptoManager.SHA256_DIGEST_SIZE, JCSystem.CLEAR_ON_RESET);
		mKeyPairLengthsHolder = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);

		mEphemeralPrivateKey = JCSystem.makeTransientByteArray(CryptoManager.EC_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
		mAuthChallenge = JCSystem.makeTransientByteArray(LONG_SIZE, JCSystem.CLEAR_ON_RESET);

		mReaderPublicKey = JCSystem.makeTransientByteArray((short)65/*Max public key size*/, JCSystem.CLEAR_ON_RESET);
		mReaderPublicKeySize = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_RESET);

		mStatus = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_RESET);


		mAcpMasksInts = JCSystem.makeTransientByteArray((short)(mAccessControlProfileMaskFailedUserAuthOffset + INT_SIZE), JCSystem.CLEAR_ON_RESET);

		mAuthAndVerificationTokensLongs = JCSystem.makeTransientByteArray((short)(mVerificationTokenTimestampOffset + LONG_SIZE), JCSystem.CLEAR_ON_RESET);

		mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

		mIntExpectedCborSizeAtEnd = JCSystem.makeTransientByteArray(INT_SIZE, JCSystem.CLEAR_ON_RESET);
		mIntCurrentCborSize = JCSystem.makeTransientByteArray((short)(INT_SIZE + SHORT_SIZE), JCSystem.CLEAR_ON_RESET);

		mHmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
				(short) (KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64 * 8), false);
		mHmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
	}

	public void reset() {
		mDigest.reset();
	}

	private void updateCborHmac(byte[] data, short dataStart, short dataLen) {
		mHmacSignature.update(data, dataStart, dataLen);
		Util.setShort(mIntCurrentCborSize, INT_SIZE, dataLen);
		ICUtil.incrementByteArray(mIntCurrentCborSize, (short)0, INT_SIZE, mIntCurrentCborSize, INT_SIZE, SHORT_SIZE);
	}

	public void processAPDU() {
		mAPDUManager.receiveAll();
		byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
		short receivingDataOffset = mAPDUManager.getOffsetIncomingData();
		short receivingDataLength = mAPDUManager.getReceivingLength();
		short le = mAPDUManager.setOutgoing(true);
		byte[] outBuffer = mAPDUManager.getSendBuffer();
		byte[] tempBuffer = mCryptoManager.getTempBuffer();
		short outGoingLength = (short)0;

		switch(receiveBuffer[ISO7816.OFFSET_INS]) {
			case ISO7816.INS_ICS_PRESENTATION_INIT:
				outGoingLength = processPresentationInit(receiveBuffer, receivingDataOffset, receivingDataLength,
										outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY_PAIR:
				outGoingLength = processCreateEphemeralKeyPair(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_CREATE_AUTH_CHALLENGE:
				outGoingLength = processCreateAuthChallenge(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_START_RETRIEVAL:
				outGoingLength = processStartRetrieval(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_SET_AUTH_TOKEN:
				outGoingLength = processSetAuthToken(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_PUSH_READER_CERT:
				outGoingLength = processPushReaderCert(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES:
				outGoingLength = processValidateAccessControlProfile(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_VALIDATE_REQUEST_MESSAGE:
				outGoingLength = processValidateRequestMessage(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_CAL_MAC_KEY:
				outGoingLength = processCalMacKey(receiveBuffer, receivingDataOffset, receivingDataLength,
						outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_START_RETRIEVE_ENTRY_VALUE:
				break;
			case ISO7816.INS_ICS_RETRIEVE_ENTRY_VALUE:
				break;
			case ISO7816.INS_ICS_FINISH_RETRIEVAL:
				break;
			case ISO7816.INS_ICS_GENERATE_SIGNING_KEY_PAIR:
				outGoingLength = processGenerateSingingKeyPair(receiveBuffer, receivingDataOffset, receivingDataLength,
											outBuffer, le, tempBuffer);
				break;
			case ISO7816.INS_ICS_PROVE_OWNERSHIP:
				break;
			case ISO7816.INS_ICS_DELETE_CREDENTIAL:
				break;
			case ISO7816.INS_ICS_UPDATE_CREDENTIAL:
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		mAPDUManager.setOutgoingLength(outGoingLength);
	}

	private short processPresentationInit(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
										 byte[] outBuffer, short le,
										 byte[] tempBuffer) {
		reset();

		boolean isTestCredential = Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1;

		//If P1P2 other than 0000 and 0001 throw exception
		if(!isTestCredential && Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

		// hold a docType in temp buffer
		short encryptedCredentialKeyOff;
		short docTypeOffset = (short)0;
		short docTypeLength = encryptedCredentialKeyOff = mCBORDecoder.readByteString(tempBuffer, docTypeOffset);
		short encryptedCredentialKeysSize = mCBORDecoder.readByteString(tempBuffer, encryptedCredentialKeyOff);

		boolean expectPopSha256 = false;

		// For feature version 202009 it's 52 bytes long and for feature version 202101 it's 86
		// bytes (the additional data is the ProofOfProvisioning SHA-256). We need
		// to support loading all feature versions.
		//
		if (encryptedCredentialKeysSize == (short)(52 + 28)) {
			/* do nothing */
		} else if (encryptedCredentialKeysSize == (short)(86 + 28)) {
			expectPopSha256 = true;
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		short outDataOffset = (short)(encryptedCredentialKeyOff + encryptedCredentialKeysSize);
		//encrypted data is in format {nonce|encryptedKeys|tag}
		if(!mCryptoManager.decryptCredentialData(isTestCredential,
				tempBuffer, (short)(encryptedCredentialKeyOff + CryptoManager.AES_GCM_IV_SIZE), (short)(encryptedCredentialKeysSize - (CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE)),
				tempBuffer, outDataOffset,
				tempBuffer, encryptedCredentialKeyOff, CryptoManager.AES_GCM_IV_SIZE,
				tempBuffer, docTypeOffset, docTypeLength,
				tempBuffer, (short)(encryptedCredentialKeyOff + encryptedCredentialKeysSize - CryptoManager.AES_GCM_TAG_SIZE), CryptoManager.AES_GCM_TAG_SIZE)) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}


		// It's supposed to look like this;
		//
		// Feature version 202009:
		//
		//         CredentialKeys = [
		//              bstr,   ; storageKey, a 128-bit AES key
		//              bstr,   ; credentialPrivKey, the private key for credentialKey
		//         ]
		//
		// Feature version 202101:
		//
		//         CredentialKeys = [
		//              bstr,   ; storageKey, a 128-bit AES key
		//              bstr,   ; credentialPrivKey, the private key for credentialKey
		//              bstr    ; proofOfProvisioning SHA-256
		//         ]
		//
		// where storageKey is 16 bytes, credentialPrivateKey is 32 bytes, and proofOfProvisioning
		// SHA-256 is 32 bytes.
		//
		if (tempBuffer[outDataOffset] != (byte)(expectPopSha256 ? 0x83 : 0x82) ||  // array of two or three elements
				tempBuffer[(short)(outDataOffset + (short)1)] != 0x50 ||                             // 16-byte bstr
				tempBuffer[(short)(outDataOffset + (short)18)] != 0x58 || tempBuffer[(short)(outDataOffset + (short)19)] != 0x20) {  // 32-byte bstr
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if (expectPopSha256) {
			if (tempBuffer[(short)(outDataOffset + (short)52)] != 0x58 || tempBuffer[(short)(outDataOffset + (short)53)] != 0x20) {  // 32-byte bstr
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		}

		mCryptoManager.setCredentialStorageKey(tempBuffer, (short)(outDataOffset + 2));
		mCryptoManager.setCredentialEcKey(tempBuffer, (short)(outDataOffset + 20));
		mCryptoManager.setStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL, isTestCredential);
		if (expectPopSha256) {
			Util.arrayCopyNonAtomic(tempBuffer, (short)(outDataOffset + 54), mProofOfProvisioningSha256, (short) 0, CryptoManager.SHA256_DIGEST_SIZE);
		}

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private short processGenerateSingingKeyPair(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
											   byte[] outBuffer, short le,
											   byte[] tempBuffer) {

		//If P1P2 other than 0000 and 0001 throw exception
		if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short docTypeOffset = (short)0, timeOffset;
		short docTypeLength = timeOffset = mCBORDecoder.readByteString(tempBuffer, docTypeOffset);
		byte intSize = mCBORDecoder.getIntegerSize();
		if(intSize == BYTE_SIZE) {
			tempBuffer[timeOffset] = mCBORDecoder.readInt8();
		} else if (intSize == SHORT_SIZE) {
			Util.setShort(tempBuffer, timeOffset, mCBORDecoder.readInt16());
		} else if(intSize == INT_SIZE) {
			mCBORDecoder.readInt32(tempBuffer, timeOffset);
		} else if(intSize == LONG_SIZE) {
			mCBORDecoder.readInt64(tempBuffer, timeOffset);
		}

		// Generate the ProofOfBinding CBOR to include in the X.509 certificate in
		// IdentityCredentialAuthenticationKeyExtension CBOR. This CBOR is defined
		// by the following CDDL
		//
		//   ProofOfBinding = [
		//     "ProofOfBinding",
		//     bstr,                  // Contains the SHA-256 of ProofOfProvisioning
		//   ]
		//
		// This array may grow in the future if other information needs to be
		// conveyed.
		//
		// The bytes of ProofOfBinding is is represented as an OCTET_STRING
		// and stored at OID 1.3.6.1.4.1.11129.2.1.26.
		//

		short proofOfBindingStart = (short)(timeOffset + intSize);
		mCBOREncoder.init(tempBuffer, (short) proofOfBindingStart, (short)50); //if cbor encoding size is greater than 50 exception will be thrown
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeTextString(STR_PROOF_OF_BINDING, (short)0, (short)STR_PROOF_OF_BINDING.length);
		mCBOREncoder.encodeByteString(mProofOfProvisioningSha256, (short)0, CryptoManager.SHA256_DIGEST_SIZE);
		short proofOfBindingLen = (short)(mCBOREncoder.getCurrentOffset() - proofOfBindingStart);

		ICUtil.shortArrayFillNonAtomic(mKeyPairLengthsHolder, (short)0, (short)2, (short)0);
		short keyBlobStart = mCBOREncoder.getCurrentOffset();
		mCryptoManager.createEcKeyPair(tempBuffer, keyBlobStart, mKeyPairLengthsHolder);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mCBOREncoder.startArray((short)2);

		//TODO generate public key certificate and encode in outBuffer, currently certificate is generated by replacing public key and pob in prebuilt certificate
		//mCBOREncoder.startByteString();//What is length of certificate
		short expectedByteStringOffset = (short)(mCBOREncoder.getCurrentOffset() + 3);//3 bytes for encoding byte string and length
		short certLen = constructPublicKeyCertificate(tempBuffer, (short)(keyBlobStart + CryptoManager.EC_KEY_SIZE), mKeyPairLengthsHolder[1],
									tempBuffer, proofOfBindingStart, proofOfBindingLen,
									outBuffer, expectedByteStringOffset);
		mCBOREncoder.startByteString(certLen);
		mCBOREncoder.increaseOffset(certLen);//Certificate is already encoded in outBuffer

		short signingKeyBlobSize = (short) (CryptoManager.AES_GCM_IV_SIZE + CryptoManager.EC_KEY_SIZE + CryptoManager.AES_GCM_TAG_SIZE);
		mCBOREncoder.startByteString(signingKeyBlobSize);
		short encOutOffset = (short)(keyBlobStart + CryptoManager.EC_KEY_SIZE);
		mCryptoManager.aesGCMEncrypt(tempBuffer, keyBlobStart, CryptoManager.EC_KEY_SIZE, //signing private key as input data
				tempBuffer, encOutOffset, //public key is no more required so overriding it
				tempBuffer, docTypeOffset, docTypeLength,
				tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS);
		Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS, outBuffer, mCBOREncoder.getCurrentOffset(), CryptoManager.AES_GCM_IV_SIZE);
		Util.arrayCopyNonAtomic(tempBuffer, encOutOffset, outBuffer, (short)(mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE), CryptoManager.EC_KEY_SIZE);
		Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_GCM_TAG_POS, outBuffer, (short) (mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE + CryptoManager.EC_KEY_SIZE), CryptoManager.AES_GCM_TAG_SIZE);

		return (short)(mCBOREncoder.getCurrentOffset() + signingKeyBlobSize);
	}

	private short constructPublicKeyCertificate(byte[] pubKey, short pubKeyOffset, short pubKeyLen,
												byte[] proofOfBinding, short pobOffset, short pobLen,
												byte[] pubCertOut, short pubCertOutOffset) {
		Util.arrayCopyNonAtomic(X509_CERT_BASE, (short)0, pubCertOut, pubCertOutOffset, (short)X509_CERT_BASE.length);
		//Set public key length
		pubCertOut[(short) (pubCertOutOffset + X509_CERT_BASE.length - 2)] = (byte)(pubKeyLen + 1);
		Util.arrayCopyNonAtomic(pubKey, pubKeyOffset, pubCertOut, (short)(pubCertOutOffset + X509_CERT_BASE.length), pubKeyLen);
		Util.arrayCopyNonAtomic(X509_DER_POB, (short)0, pubCertOut, (short)(pubCertOutOffset + X509_CERT_BASE.length + pubKeyLen), (short)X509_DER_POB.length);

		Util.arrayCopyNonAtomic(proofOfBinding, pobOffset, pubCertOut, (short)(pubCertOutOffset + X509_CERT_BASE.length + pubKeyLen + X509_DER_POB.length), pobLen);
		short tbsCertLen = (short)(X509_CERT_BASE.length + pubKeyLen + X509_DER_POB.length + pobLen -  X509_CERT_POS_TOTAL_LEN - SHORT_SIZE);
		Util.arrayCopyNonAtomic(X509_DER_SIGNATURE, (short)0, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen), (short)(X509_DER_SIGNATURE.length));

		short signLen = mCryptoManager.ecSignWithSHA256Digest(pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE), tbsCertLen, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length));
		pubCertOut[(short) (pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length - 2)] = (byte)(signLen + 1);
		Util.setShort(pubCertOut, (short) (pubCertOutOffset + X509_CERT_POS_TOTAL_LEN), (short)(tbsCertLen + X509_DER_SIGNATURE.length + signLen));

		return (short)(X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length + signLen);
	}

	private short extractPublicKeyFromCertificate(byte[] cert, short certOffset, short certLen,
												  byte[] outPubKey, short outPubKeyOffset) {
		short pubKeyDerIndex = (short)0;
		for(short i = (short)0; i < certLen; i++) {
			short matches = (short) 0;
			for(short j = (short)0; j < (short)DER_PUB_KEY_OID.length && ((i + j) < certLen - 1); j++) {
				if(cert[(short)(certOffset + i + j)] == DER_PUB_KEY_OID[j]) {
					matches++;
				} else {
					break;
				}
			}
			if(matches == (short)DER_PUB_KEY_OID.length) {
				for (short j = (short)0; j < (short) DER_EC_KEY_CURVE_OID.length && ((i + (short)DER_PUB_KEY_OID.length + j) < certLen - 1); j++) {
					if (cert[(short) (certOffset + i + (short)DER_PUB_KEY_OID.length + j)] == DER_EC_KEY_CURVE_OID[j]) {
						matches++;
					} else {
						break;
					}
				}
			}
			if(matches == (short)(DER_PUB_KEY_OID.length + DER_EC_KEY_CURVE_OID.length) && cert[(short)(certOffset + i + matches)] == 0x03) {
				pubKeyDerIndex = (short)(i + matches + 1);
				break;
			}
		}
		if(pubKeyDerIndex > (short)0) {
			byte pubKeyLen = (byte)(cert[(short)(certOffset + pubKeyDerIndex)] - 1);
			Util.arrayCopyNonAtomic(cert, (short)(certOffset + pubKeyDerIndex + 2), outPubKey, outPubKeyOffset, pubKeyLen);
			return pubKeyLen;
		}
		return (short)0;
	}

	private short processCreateEphemeralKeyPair(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
											   byte[] outBuffer, short le,
											   byte[] tempBuffer) {

		//If P1P2 other than 0000 and 0001 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		ICUtil.shortArrayFillNonAtomic(mKeyPairLengthsHolder, (short)0, (short)2, (short)0);
		short keyBlobStart = (short) 0;
		mCryptoManager.createEcKeyPair(tempBuffer, keyBlobStart, mKeyPairLengthsHolder);
		Util.arrayCopyNonAtomic(tempBuffer, keyBlobStart, mEphemeralPrivateKey, (short)0, CryptoManager.EC_KEY_SIZE);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeByteString(tempBuffer, keyBlobStart, CryptoManager.EC_KEY_SIZE);
		return mCBOREncoder.getCurrentOffset();
	}

	private short processCreateAuthChallenge(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
											byte[] outBuffer, short le,
											byte[] tempBuffer) {
		//If P1P2 other than 0000 and 0001 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		short challengeOffset = (short) 0;
		do {
			mCryptoManager.generateRandomData(tempBuffer, challengeOffset, LONG_SIZE);
			Util.arrayCopyNonAtomic(tempBuffer, challengeOffset, mAuthChallenge, (short) 0, LONG_SIZE);
		} while (tempBuffer[challengeOffset] == 0x00);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt64(tempBuffer, challengeOffset);
		return mCBOREncoder.getCurrentOffset();
	}

	private short processPushReaderCert(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
									   byte[] outBuffer, short le,
									   byte[] tempBuffer){
		//If P1P2 other than 0000 and 0001 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short outPubKeyOffset;
		short certLen = outPubKeyOffset = mCBORDecoder.readByteString(tempBuffer, (short)0);
		short pubKeySize = extractPublicKeyFromCertificate(tempBuffer, (short)0, certLen, tempBuffer, outPubKeyOffset);
		Util.arrayCopyNonAtomic(tempBuffer, outPubKeyOffset, mReaderPublicKey, (short)0, pubKeySize);
		mReaderPublicKeySize[(short)0] = pubKeySize;

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private short processStartRetrieval(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
									   byte[] outBuffer, short le,
									   byte[] tempBuffer) {
		//If P1P2 other than 0000 and 0001 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		// HAL may use this object multiple times to retrieve data so need to reset various
		// state objects here.
		mStatus[mRequestMessageValidated] = false;
		mStatus[mBuildCbor] = false;
		Util.arrayFillNonAtomic(mAcpMasksInts, mAccessControlProfileMaskValidatedOffset, INT_SIZE, (byte)0);
		Util.arrayFillNonAtomic(mAcpMasksInts, mAccessControlProfileMaskUsesReaderAuthOffset, INT_SIZE, (byte)0);
		Util.arrayFillNonAtomic(mAcpMasksInts, mAccessControlProfileMaskFailedReaderAuthOffset, INT_SIZE, (byte)0);
		Util.arrayFillNonAtomic(mAcpMasksInts, mAccessControlProfileMaskFailedUserAuthOffset, INT_SIZE, (byte)0);
		mReaderPublicKeySize[0] = 0;

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private short processSetAuthToken(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
									  byte[] outBuffer, short le,
									  byte[] tempBuffer) {
		//If P1P2 other than 0000 and 0001 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		Util.arrayFillNonAtomic(tempBuffer, (short)0, LONG_SIZE, (byte)0);
		if(Util.arrayCompare(mAuthChallenge, (short) 0, tempBuffer, (short) 0, LONG_SIZE) == (byte)0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		mCBORDecoder.skipEntry();//challenge
		mCBORDecoder.skipEntry();//secureUserId
		mCBORDecoder.skipEntry();//authenticatorId
		mCBORDecoder.skipEntry();//hardwareAuthenticatorType
		mCBORDecoder.skipEntry();//timeStamp
		mCBORDecoder.skipEntry();//mac
		byte intSize = mCBORDecoder.getIntegerSize();
		if(intSize < LONG_SIZE) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short verificationTokenChallengeOffset = (short)0;//verificationTokenChallenge
		mCBORDecoder.readInt64(tempBuffer, verificationTokenChallengeOffset);
		if(Util.arrayCompare(tempBuffer, verificationTokenChallengeOffset, mAuthChallenge, (short)0, LONG_SIZE) != 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		if(!validateAuthToken(receiveBuffer, receivingDataOffset, receivingDataLength, tempBuffer)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short authTokenChallengeOffsetLen = ICUtil.readUint(mCBORDecoder, tempBuffer, (short)0);//challenge
		Util.arrayCopyNonAtomic(tempBuffer, (short)0, mAuthAndVerificationTokensLongs, (short)(mAuthTokenChallengeOffset + LONG_SIZE - authTokenChallengeOffsetLen), authTokenChallengeOffsetLen);
		short authTokenSecureUserIdLen = ICUtil.readUint(mCBORDecoder, tempBuffer, (short)0);//secureUserId
		Util.arrayCopyNonAtomic(tempBuffer, (short)0, mAuthAndVerificationTokensLongs, (short)(mAuthTokenSecureUserIdOffset + LONG_SIZE - authTokenSecureUserIdLen), authTokenSecureUserIdLen);
		mCBORDecoder.skipEntry();//authenticatorId
		mCBORDecoder.skipEntry();//hardwareAuthenticatorType
		short authTokenTimeStampLen = ICUtil.readUint(mCBORDecoder, tempBuffer, (short)0);//timestamp
		Util.arrayCopyNonAtomic(tempBuffer, (short)0, mAuthAndVerificationTokensLongs, (short)(mAuthTokenTimestampOffset + LONG_SIZE - authTokenTimeStampLen), authTokenTimeStampLen);
		mCBORDecoder.skipEntry();//mac
		mCBORDecoder.skipEntry();//verificationTokenChallenge
		short verificationTokenTimeStampLen = ICUtil.readUint(mCBORDecoder, tempBuffer, (short)0);//verificationTokenTimestamp
		Util.arrayCopyNonAtomic(tempBuffer, (short)0, mAuthAndVerificationTokensLongs, (short)(mVerificationTokenTimestampOffset + LONG_SIZE - verificationTokenTimeStampLen), verificationTokenTimeStampLen);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private boolean validateAuthToken(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
									  byte[] tempBuffer) {
		// Here's where we would validate the passed-in |authToken| to assure ourselves
		// that it comes from the e.g. biometric hardware and wasn't made up by an attacker.
		//
		// However this involves calculating the MAC which requires access to the to
		// a pre-shared key which we don't have...
		//
		//TODO get the detail from Chirag about how to implement from Keymaster mint
		return false;
	}

	private short processValidateAccessControlProfile(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
													  byte[] outBuffer, short le,
													  byte[] tempBuffer) {

		Util.arrayFillNonAtomic(tempBuffer, (short)0, CryptoManager.TEMP_BUFFER_SIZE, (byte)0);
		//If P1P2 other than 0000 and 0001 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		byte intSize = mCBORDecoder.getIntegerSize();
		if(intSize != BYTE_SIZE) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		byte id = mCBORDecoder.readInt8();
		if(id < (byte)0 || id >= (byte)32) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short timeoutMillisOffset = (short)0;
		boolean userAuthenticationRequired = mCBORDecoder.readBoolean();// userAuthenticationRequired
		short timeoutMillisLen = ICUtil.readUint(mCBORDecoder, tempBuffer, (short)(timeoutMillisOffset + LONG_SIZE));// timeoutMillis
		timeoutMillisLen = Util.arrayCopyNonAtomic(tempBuffer, (short)(timeoutMillisOffset + LONG_SIZE), tempBuffer, timeoutMillisOffset, timeoutMillisLen);
		short secureUserIdOffset = (short) (timeoutMillisOffset + timeoutMillisLen);
		short secureUserIdLen = ICUtil.readUint(mCBORDecoder, tempBuffer, secureUserIdOffset);// secureUserId
		secureUserIdLen = Util.arrayCopyNonAtomic(tempBuffer, (short)(secureUserIdOffset + LONG_SIZE), tempBuffer, secureUserIdOffset, secureUserIdLen);
		short readerCertOffset = (short) (secureUserIdOffset + secureUserIdLen);
		short readerCertLen = mCBORDecoder.readByteString(tempBuffer, readerCertOffset);// reader certificate
		short macOffset = (short) (readerCertOffset + readerCertLen);
		short macLen = mCBORDecoder.readByteString(tempBuffer, macOffset);//mac - it contains only NONCE and TAG
		short freeOffset = (short)(macOffset + macLen);

		short outLength = ICUtil.constructCBORAccessControl(mCBORDecoder, mCBOREncoder,
				receiveBuffer, receivingDataOffset, receivingDataLength,
				outBuffer, (short)0, le, true);

		if(!mCryptoManager.aesGCMDecrypt(tempBuffer, freeOffset, (short)0, //no encrypted data
									tempBuffer, freeOffset, //No decrypted out data
									outBuffer, (short)0, outLength, //Auth data
									tempBuffer, macOffset)) { //mac
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		boolean passedUserAuth = checkUserAuth(userAuthenticationRequired, tempBuffer, timeoutMillisOffset,
				tempBuffer, secureUserIdOffset, tempBuffer, freeOffset);
		boolean passedReaderAuth = checkReaderAuth(tempBuffer, readerCertOffset, readerCertLen, tempBuffer, freeOffset);

		//TODO is this correct implementation?
		mAcpMasksInts[mAccessControlProfileMaskValidatedOffset + (INT_SIZE - (id / (short)8)) - 1] |= ((short)1 << (id % (short)8));
		if(readerCertLen > 0) {
			mAcpMasksInts[mAccessControlProfileMaskUsesReaderAuthOffset + (INT_SIZE - (id / (short)8)) - 1] |= ((short)1 << (id % (short)8));
		}
		if(!passedReaderAuth) {
			mAcpMasksInts[mAccessControlProfileMaskFailedReaderAuthOffset + (INT_SIZE - (id / (short)8)) - 1] |= ((short)1 << (id % (short)8));
		}
		if(!passedUserAuth) {
			mAcpMasksInts[mAccessControlProfileMaskFailedUserAuthOffset + (INT_SIZE - (id / (short)8)) - 1] |= ((short)1 << (id % (short)8));
		}

		boolean isAccessGranted = passedUserAuth && passedReaderAuth;

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeBoolean(isAccessGranted);
		return mCBOREncoder.getCurrentOffset();
	}

	private boolean checkUserAuth(boolean userAuthRequired,
								  byte[] timeOutMillis, short timeOutMillisOffset,
								  byte[] secureUserId, short secureUserIdOffset,
								  byte[] tempBuffer, short tempOffset) {
		if(!userAuthRequired) {
			return true;
		}
		if(Util.arrayCompare(secureUserId, secureUserIdOffset, mAuthAndVerificationTokensLongs, mAuthTokenSecureUserIdOffset, LONG_SIZE) != (byte)0) {
			return false;
		}
		Util.arrayFillNonAtomic(tempBuffer, tempOffset, LONG_SIZE, (byte)0);
		if(Util.arrayCompare(tempBuffer, tempOffset, timeOutMillis, timeOutMillisOffset, LONG_SIZE) == (byte)0) {
			if (Util.arrayCompare(mAuthChallenge, (short) 0, mAuthAndVerificationTokensLongs, mAuthTokenChallengeOffset, LONG_SIZE) != (byte) 0) {
				return false;
			}
		}
		if(Util.arrayCompare(mAuthAndVerificationTokensLongs, mAuthTokenTimestampOffset, mAuthAndVerificationTokensLongs, mVerificationTokenTimestampOffset, LONG_SIZE) > (byte)0) {
			return false;
		}
		if(Util.arrayCompare(timeOutMillis, timeOutMillisOffset, tempBuffer, tempOffset, LONG_SIZE) > (byte)0) {
			ICUtil.incrementByteArray(tempBuffer, tempOffset, LONG_SIZE, timeOutMillis, timeOutMillisOffset, LONG_SIZE);
			ICUtil.incrementByteArray(tempBuffer, tempOffset, LONG_SIZE, mAuthAndVerificationTokensLongs, mAuthTokenTimestampOffset, LONG_SIZE);
			if(Util.arrayCompare(mAuthAndVerificationTokensLongs, mVerificationTokenTimestampOffset, tempBuffer, tempOffset, LONG_SIZE) > (byte)0) {
				return false;
			}
		}

		return true;
	}

	private boolean checkReaderAuth(byte[] readerCert, short readerCertOffset, short readerCertLen,
									byte[] tempBuffer, short tempOffset) {
		if(readerCertLen == (short)0) {
			return false;
		}

		// Remember in this case certificate equality is done by comparing public
		// keys, not bitwise comparison of the certificates.
		//
		short pubKeyLen = extractPublicKeyFromCertificate(readerCert, readerCertOffset, readerCertLen, tempBuffer, tempOffset);
		if(pubKeyLen == 0) {
			return false;
		}
		if(mReaderPublicKeySize[(short)0] != pubKeyLen || (Util.arrayCompare(mReaderPublicKey, (short)0, tempBuffer, tempOffset, pubKeyLen) != (byte)0)) {
			return false;
		}

		return true;
	}

	private short processValidateRequestMessage(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
								   byte[] outBuffer, short le,
								   byte[] tempBuffer) {

		//If P1P2 other than 0000 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		if(mReaderPublicKeySize[0] == (short)0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short sessionTranscriptOffset = (short)0;
		short sessionTranscriptLen = mCBORDecoder.readByteString(tempBuffer, sessionTranscriptOffset);
		short requestMessageOffset = (short)(sessionTranscriptOffset + sessionTranscriptLen);
		short requestMessageLen = mCBORDecoder.readByteString(tempBuffer, requestMessageOffset);
		short readerSignatureOfTBSOffset = (short)(requestMessageOffset + requestMessageLen);
		short coseSingAlg = (mCBORDecoder.getMajorType() & CBORBase.MAJOR_TYPE_MASK) == CBORBase.TYPE_NEGATIVE_INTEGER ? (byte)(-1 - mCBORDecoder.readInt8()) : mCBORDecoder.readInt8();
		short readerSignatureOfTBSLen = mCBORDecoder.readByteString(tempBuffer, readerSignatureOfTBSOffset);
		short tempShaOffset = (short)(readerSignatureOfTBSOffset + readerSignatureOfTBSLen);

		// Right now we only support ECDSA with SHA-256 (e.g. ES256).
		//
		if(coseSingAlg != COSE_SIGN_ALG) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		// What we're going to verify is the COSE ToBeSigned structure which
		// looks like the following:
		//
		//   Sig_structure = [
		//     context : "Signature" / "Signature1" / "CounterSignature",
		//     body_protected : empty_or_serialized_map,
		//     ? sign_protected : empty_or_serialized_map,
		//     external_aad : bstr,
		//     payload : bstr
		//   ]
		//
		// So we're going to build that CBOR...
		//
		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)4);
		mCBOREncoder.encodeTextString(STR_SIGNATURE1, (short)0, (short)STR_SIGNATURE1.length);

		// The COSE Encoded protected headers is just a single field with
		// COSE_LABEL_ALG (1) -> coseSignAlg (e.g. -7). For simplicitly we just
		// hard-code the CBOR encoding:
		mCBOREncoder.encodeByteString(COSE_ENCODED_PROTECTED_HEADERS_ECDSA, (short)0, (short)COSE_ENCODED_PROTECTED_HEADERS_ECDSA.length);

		// External_aad is the empty bstr
		mCBOREncoder.encodeByteString(tempBuffer, (short)0, (short)0);

		// For the payload, the _encoded_ form follows here. We handle this by simply
		// opening a bstr, and then writing the CBOR. This requires us to know the
		// size of said bstr, ahead of time... the CBOR to be written is
		//
		//   ReaderAuthentication = [
		//      "ReaderAuthentication",
		//      SessionTranscript,
		//      ItemsRequestBytes
		//   ]
		//
		//   ItemsRequestBytes = #6.24(bstr .cbor ItemsRequest)
		//
		//   ReaderAuthenticationBytes = #6.24(bstr .cbor ReaderAuthentication)
		//
		// which is easily calculated below
		//
		short calculatedSize = 0;
		calculatedSize += 1;  // Array of size 3
		calculatedSize += 1;  // "ReaderAuthentication" less than 24 bytes
		calculatedSize += STR_READER_AUTHENTICATION.length;  // Don't include trailing NUL
		calculatedSize += sessionTranscriptLen;               // Already CBOR encoded
		calculatedSize += 2;  // Semantic tag EIC_CBOR_SEMANTIC_TAG_ENCODED_CBOR (24)
		calculatedSize += 1 + ICUtil.calCborAdditionalLengthBytesFor(requestMessageLen);
		calculatedSize += requestMessageLen;

		// However note that we're authenticating ReaderAuthenticationBytes which
		// is a tagged bstr of the bytes of ReaderAuthentication. So need to get
		// that in front.
		short rabCalculatedSize = 0;
		rabCalculatedSize += 2;  // Semantic tag EIC_CBOR_SEMANTIC_TAG_ENCODED_CBOR (24)
		rabCalculatedSize += 1 + ICUtil.calCborAdditionalLengthBytesFor(calculatedSize);
		rabCalculatedSize += calculatedSize;

		// Begin the bytestring for ReaderAuthenticationBytes;
		mCBOREncoder.startByteString(rabCalculatedSize);
		mCBOREncoder.encodeTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR);
		mCBOREncoder.startByteString(calculatedSize);

		// And now that we know the size, let's fill it in...
		//
		short payloadOffset = mCBOREncoder.getCurrentOffset();
		mCBOREncoder.startArray((short)3);
		mCBOREncoder.encodeTextString(STR_READER_AUTHENTICATION, (short)0, (short)STR_READER_AUTHENTICATION.length);
		mCBOREncoder.encodeRawData(tempBuffer, sessionTranscriptOffset, sessionTranscriptLen);
		mCBOREncoder.encodeTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR);
		mCBOREncoder.startByteString(requestMessageLen);
		mCBOREncoder.encodeRawData(tempBuffer, requestMessageOffset, requestMessageLen);

		if(mCBOREncoder.getCurrentOffset() != (short)(payloadOffset + calculatedSize)) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		mDigest.reset();
		short tempShaLen = mDigest.doFinal(mCBOREncoder.getBuffer(), (short)0, mCBOREncoder.getCurrentOffset(), tempBuffer, tempShaOffset);
		if(!mCryptoManager.ecVerifyWithNoDigest(mReaderPublicKey, (short)0, mReaderPublicKeySize[0],
								tempBuffer, tempShaOffset, tempShaLen,
								tempBuffer, readerSignatureOfTBSOffset, readerSignatureOfTBSLen)) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		mStatus[mRequestMessageValidated] = true;

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private short processCalMacKey(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
								  byte[] outBuffer, short le,
								  byte[] tempBuffer) {

		//If P1P2 other than 0000 throw exception
		if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short sessionTranscriptOffset = (short)0;
		short sessionTranscriptLen = mCBORDecoder.readByteString(tempBuffer, sessionTranscriptOffset);
		short readerEphemeralPubKeyOffset = (short)(sessionTranscriptOffset + sessionTranscriptLen);
		short readerEphemeralPubKeyLen = mCBORDecoder.readByteString(tempBuffer, readerEphemeralPubKeyOffset);
		short signingKeyBlobOffset = (short)(readerEphemeralPubKeyOffset + readerEphemeralPubKeyLen);
		short signingKeyBlobLen = mCBORDecoder.readByteString(tempBuffer, signingKeyBlobOffset);
		short docTypeOffset = (short)(signingKeyBlobOffset + signingKeyBlobLen);
		short docTypeLen = mCBORDecoder.readByteString(tempBuffer, docTypeOffset);
		if(signingKeyBlobLen != (short)60) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		byte numNamespacesWithValuesLen = mCBORDecoder.getIntegerSize();
		short numNamespacesWithValuesOffset = (short)(docTypeOffset + docTypeLen);
		if(numNamespacesWithValuesLen == BYTE_SIZE) {
			tempBuffer[numNamespacesWithValuesOffset] = mCBORDecoder.readInt8();
		} else if(numNamespacesWithValuesLen == SHORT_SIZE) {
			Util.setShort(tempBuffer, numNamespacesWithValuesOffset, mCBORDecoder.readInt16());
		} else if(numNamespacesWithValuesLen == INT_SIZE) {
			mCBORDecoder.readInt32(tempBuffer, numNamespacesWithValuesOffset);
		} else if(numNamespacesWithValuesLen == LONG_SIZE) {
			mCBORDecoder.readInt64(tempBuffer, numNamespacesWithValuesOffset);
		}

		byte expectedDeviceNamespacesSizeLen = mCBORDecoder.getIntegerSize();
		short expectedDeviceNamespacesSizeOffset = (short)(numNamespacesWithValuesOffset + numNamespacesWithValuesLen);
		if(expectedDeviceNamespacesSizeLen == BYTE_SIZE) {
			tempBuffer[expectedDeviceNamespacesSizeOffset] = mCBORDecoder.readInt8();
		} else if(expectedDeviceNamespacesSizeLen == SHORT_SIZE) {
			Util.setShort(tempBuffer, expectedDeviceNamespacesSizeOffset, mCBORDecoder.readInt16());
		} else if(expectedDeviceNamespacesSizeLen == INT_SIZE) {
			mCBORDecoder.readInt32(tempBuffer, expectedDeviceNamespacesSizeOffset);
		} else if(expectedDeviceNamespacesSizeLen == LONG_SIZE) {
			mCBORDecoder.readInt64(tempBuffer, expectedDeviceNamespacesSizeOffset);
		}

		short nonceAndTagOffset = (short)(expectedDeviceNamespacesSizeOffset + expectedDeviceNamespacesSizeLen);
		short nonceAndTagLen = Util.arrayCopyNonAtomic(tempBuffer, signingKeyBlobOffset, tempBuffer, nonceAndTagOffset, CryptoManager.AES_GCM_IV_SIZE);
		nonceAndTagLen += Util.arrayCopyNonAtomic(tempBuffer, (short)(signingKeyBlobOffset + signingKeyBlobLen - CryptoManager.AES_GCM_TAG_SIZE),
				tempBuffer, (short)(nonceAndTagOffset + CryptoManager.AES_GCM_IV_SIZE), CryptoManager.AES_GCM_TAG_SIZE);


		short signingKeyPrivOffset = (short)(nonceAndTagOffset + nonceAndTagLen);
		if(!mCryptoManager.aesGCMDecrypt(tempBuffer, (short)(signingKeyBlobOffset + CryptoManager.AES_GCM_IV_SIZE),
				(short)(signingKeyBlobLen - CryptoManager.AES_GCM_IV_SIZE - CryptoManager.AES_GCM_TAG_SIZE),
				tempBuffer, signingKeyPrivOffset,
				tempBuffer, (short)(docTypeOffset), docTypeLen,
				tempBuffer, nonceAndTagOffset)) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short sharedSecretOffset = (short) (signingKeyPrivOffset + CryptoManager.EC_KEY_SIZE);
		short sharedSecretLen = mCryptoManager.createECDHSecret(tempBuffer, signingKeyPrivOffset, CryptoManager.EC_KEY_SIZE,
										tempBuffer, readerEphemeralPubKeyOffset, readerEphemeralPubKeyLen,
										tempBuffer, sharedSecretOffset);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.encodeTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR);
		mCBOREncoder.encodeByteString(tempBuffer, sessionTranscriptOffset, sessionTranscriptLen);
		short saltOffset = (short) (sharedSecretOffset + sharedSecretLen);
		mDigest.reset();
		short saltLen = mDigest.doFinal(mCBOREncoder.getBuffer(), (short)0, mCBOREncoder.getCurrentOffset(), tempBuffer, saltOffset);
		short derivedKeyOffset = (short) (saltOffset + saltLen);
		short expectedKeySize = (short)32;
		short derivedKeyLen = mCryptoManager.hkdf(tempBuffer, sharedSecretOffset, sharedSecretLen, tempBuffer, saltOffset, saltLen,
								EMAC_KEY_INFO, (short)0, (short)EMAC_KEY_INFO.length, tempBuffer, derivedKeyOffset, expectedKeySize);

		short tempBuffFreeOffset = (short)(derivedKeyOffset + derivedKeyLen);
		mCBOREncoder.init(outBuffer, (short) 0, le);
		mHmacKey.setKey(tempBuffer, derivedKeyOffset, derivedKeyLen);
		mHmacSignature.init(mHmacKey, Signature.MODE_SIGN);
		mStatus[mBuildCbor] = true;

		// What we're going to calculate the HMAC-SHA256 is the COSE ToBeMaced
		// structure which looks like the following:
		//
		// MAC_structure = [
		//   context : "MAC" / "MAC0",
		//   protected : empty_or_serialized_map,
		//   external_aad : bstr,
		//   payload : bstr
		// ]
		//
		mCBOREncoder.startArray((short)4);
		mCBOREncoder.encodeTextString(MAC0, (short)0, (short)MAC0.length);

		// The COSE Encoded protected headers is just a single field with
		// COSE_LABEL_ALG (1) -> COSE_ALG_HMAC_256_256 (5). For simplicitly we just
		// hard-code the CBOR encoding:
		mCBOREncoder.encodeByteString(COSE_ENCODED_PROTECTED_HEADERS_HMAC, (short)0, (short) COSE_ENCODED_PROTECTED_HEADERS_HMAC.length);

		// We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
		// so external_aad is the empty bstr
		mCBOREncoder.encodeByteString(tempBuffer, (short)0, (short)0);

		// For the payload, the _encoded_ form follows here. We handle this by simply
		// opening a bstr, and then writing the CBOR. This requires us to know the
		// size of said bstr, ahead of time... the CBOR to be written is
		//
		//   DeviceAuthentication = [
		//      "DeviceAuthentication",
		//      SessionTranscript,
		//      DocType,                ; DocType as used in Documents structure in OfflineResponse
		//      DeviceNameSpacesBytes
		//   ]
		//
		//   DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)
		//
		//   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
		//
		// which is easily calculated below
		//
		short calculatedSize = 0;
		calculatedSize += 1;  // Array of size 4
		calculatedSize += 1;  // "DeviceAuthentication" less than 24 bytes
		calculatedSize += (short)STR_DEVICE_AUTHENTICATION.length;  // Don't include trailing NUL
		calculatedSize += sessionTranscriptLen;               // Already CBOR encoded
		calculatedSize += 1 + ICUtil.calCborAdditionalLengthBytesFor(docTypeLen) + docTypeLen;
		calculatedSize += 2;  // Semantic tag EIC_CBOR_SEMANTIC_TAG_ENCODED_CBOR (24)

		calculatedSize += 1 + ICUtil.calCborAdditionalLengthBytesFor(tempBuffer, expectedDeviceNamespacesSizeOffset, expectedDeviceNamespacesSizeLen);
		if(expectedDeviceNamespacesSizeLen == BYTE_SIZE) {
			calculatedSize += tempBuffer[expectedDeviceNamespacesSizeOffset];
		} else if(expectedDeviceNamespacesSizeLen == SHORT_SIZE) {
			calculatedSize += Util.getShort(tempBuffer, expectedDeviceNamespacesSizeOffset);
		} else {
			//TODO if expectedDeviceNamespaceSize could be greater than short value we need to defile calculatedSize as integer or long also
			/*Util.arrayFillNonAtomic(tempBuffer, tempBuffFreeOffset, expectedDeviceNamespacesSizeLen, (byte)0);
			 *ICUtil.incrementByteArray(tempBuffer, tempBuffFreeOffset, expectedDeviceNamespacesSizeLen, tempBuffer, expectedDeviceNamespacesSizeOffset, expectedDeviceNamespacesSizeLen);
			 *ICUtil.incrementByteArray(tempBuffer, tempBuffFreeOffset, expectedDeviceNamespacesSizeLen, tempBuffer, calculatedSizeOffset, calculatedSizeLen);
			 */
		}

		// However note that we're authenticating DeviceAuthenticationBytes which
		// is a tagged bstr of the bytes of DeviceAuthentication. So need to get
		// that in front.
		short dabCalculatedSize = 0;
		dabCalculatedSize += 2;  // Semantic tag EIC_CBOR_SEMANTIC_TAG_ENCODED_CBOR (24)
		dabCalculatedSize += 1 + ICUtil.calCborAdditionalLengthBytesFor(calculatedSize);
		dabCalculatedSize += calculatedSize;

		// Begin the bytestring for DeviceAuthenticationBytes;
		mCBOREncoder.startArray(dabCalculatedSize);
		mCBOREncoder.encodeTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR);
		// Begins the bytestring for DeviceAuthentication;
		mCBOREncoder.startByteString(calculatedSize);

		mCBOREncoder.startArray((short)4);
		mCBOREncoder.encodeTextString(STR_DEVICE_AUTHENTICATION, (short)0, (short)STR_DEVICE_AUTHENTICATION.length);
		mCBOREncoder.encodeRawData(tempBuffer, sessionTranscriptOffset, sessionTranscriptLen);
		mCBOREncoder.encodeTextString(tempBuffer, docTypeOffset, docTypeLen);

		// For the payload, the _encoded_ form follows here. We handle this by simply
		// opening a bstr, and then writing the CBOR. This requires us to know the
		// size of said bstr, ahead of time.
		mCBOREncoder.encodeTag(CBOR_SEMANTIC_TAG_ENCODED_CBOR);
		mCBOREncoder.startByteString(tempBuffer, expectedDeviceNamespacesSizeOffset, expectedDeviceNamespacesSizeLen);

		Util.arrayCopyNonAtomic(tempBuffer, expectedDeviceNamespacesSizeOffset, mIntExpectedCborSizeAtEnd, (short)(INT_SIZE - expectedDeviceNamespacesSizeLen), expectedDeviceNamespacesSizeLen);
		Util.setShort(tempBuffer, tempBuffFreeOffset, mCBOREncoder.getCurrentOffset());
		ICUtil.incrementByteArray(mIntExpectedCborSizeAtEnd, (short)0, INT_SIZE, tempBuffer, tempBuffFreeOffset, SHORT_SIZE);

		if(numNamespacesWithValuesLen == BYTE_SIZE) {
			mCBOREncoder.startMap(tempBuffer[numNamespacesWithValuesOffset]);
		} else if(numNamespacesWithValuesLen == SHORT_SIZE) {
			mCBOREncoder.startMap(Util.getShort(tempBuffer, numNamespacesWithValuesOffset));
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		updateCborHmac(outBuffer, (short)0, mCBOREncoder.getCurrentOffset());

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}
}
