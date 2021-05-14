package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

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

    private final byte[] proofOfProvisioningSha256;

	private final byte[] ephemeralPrivateKey;

	private final byte[] readerPublicKey;
	private final short[] readerPublicKeySize;

    private final short[] keyPairLengthsHolder;

    private final byte[] authChallenge;

	// This is set to true only if eicPresentationValidateRequestMessage() successfully
	// validated the requestMessage.
	//
	// Why even record this? Because there's no requirement the HAL actually calls that
	// function and we validate ACPs before it's called... so it's possible that a
	// compromised HAL could trick us into marking ACPs as authorized while they in fact
	// aren't.
	byte requestMessageValidated = (byte)0;
	byte buildCbor = (byte)1;
	private final boolean[] status;

	// These are bitmasks indicating which of the possible 32 access control profiles are
	// authorized. They are built up by eicPresentationValidateAccessControlProfile().
	//
	private final byte accessControlProfileMaskValidatedOffset = (byte) 0;
	private final byte accessControlProfileMaskUsesReaderAuthOffset = (byte)(accessControlProfileMaskValidatedOffset + LONG_SIZE);
	private final byte accessControlProfileMaskFailedReaderAuthOffset = (byte)(accessControlProfileMaskUsesReaderAuthOffset + LONG_SIZE);
	private final byte accessControlProfileMaskFailedUserAuthOffset = (byte)(accessControlProfileMaskFailedReaderAuthOffset + LONG_SIZE);
	private final byte[] acpMasksInts;

	// Set by eicPresentationSetAuthToken() and contains the fields
	// from the passed in authToken and verificationToken.
	//
	byte authChallengeOffset = (byte) 0;
	byte authTokenChallengeOffset = (byte) (authChallengeOffset + LONG_SIZE);
	byte authTokenSecureUserIdOffset = (byte)(authTokenChallengeOffset + LONG_SIZE);
	byte authTokenTimestampOffset = (byte)(authTokenSecureUserIdOffset + LONG_SIZE);
	byte verificationTokenTimestampOffset = (byte)(authTokenTimestampOffset + LONG_SIZE);
	private final byte[] authAndVerificationTokensLongs;

	public JCICPresentation(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
		proofOfProvisioningSha256 = JCSystem.makeTransientByteArray(CryptoManager.SHA256_DIGEST_SIZE, JCSystem.CLEAR_ON_RESET);
		keyPairLengthsHolder = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);

		ephemeralPrivateKey = JCSystem.makeTransientByteArray(CryptoManager.EC_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
		authChallenge = JCSystem.makeTransientByteArray(LONG_SIZE, JCSystem.CLEAR_ON_RESET);

		readerPublicKey = JCSystem.makeTransientByteArray((short)65/*Max public key size*/, JCSystem.CLEAR_ON_RESET);
		readerPublicKeySize = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_RESET);

		status = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_RESET);


		acpMasksInts = JCSystem.makeTransientByteArray((short)(accessControlProfileMaskFailedUserAuthOffset + INT_SIZE), JCSystem.CLEAR_ON_RESET);

		authAndVerificationTokensLongs = JCSystem.makeTransientByteArray((short)(verificationTokenTimestampOffset + LONG_SIZE), JCSystem.CLEAR_ON_RESET);
	}

	public void reset() {

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
				break;
			case ISO7816.INS_ICS_VALIDATE_REQUEST_MESSAGE:
				break;
			case ISO7816.INS_ICS_CAL_MAC_KEY:
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
			Util.arrayCopyNonAtomic(tempBuffer, (short)(outDataOffset + 54), proofOfProvisioningSha256, (short) 0, CryptoManager.SHA256_DIGEST_SIZE);
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
		mCBOREncoder.encodeByteString(proofOfProvisioningSha256, (short)0, CryptoManager.SHA256_DIGEST_SIZE);
		short proofOfBindingLen = (short)(mCBOREncoder.getCurrentOffset() - proofOfBindingStart);

		ICUtil.shortArrayFillNonAtomic(keyPairLengthsHolder, (short)0, (short)2, (short)0);
		short keyBlobStart = mCBOREncoder.getCurrentOffset();
		mCryptoManager.createEcKeyPair(tempBuffer, keyBlobStart, keyPairLengthsHolder);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mCBOREncoder.startArray((short)2);

		//TODO generate public key certificate and encode in outBuffer, currently certificate is generated by replacing public key and pob in prebuilt certificate
		//mCBOREncoder.startByteString();//What is length of certificate
		short expectedByteStringOffset = (short)(mCBOREncoder.getCurrentOffset() + 3);//3 bytes for encoding byte string and length
		short certLen = constructPublicKeyCertificate(tempBuffer, (short)(keyBlobStart + CryptoManager.EC_KEY_SIZE), keyPairLengthsHolder[1],
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

		short signLen = mCryptoManager.ecSign(pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE), tbsCertLen, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length));
		pubCertOut[(short) (pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length - 2)] = (byte)(signLen + 1);
		Util.setShort(pubCertOut, (short) (pubCertOutOffset + X509_CERT_POS_TOTAL_LEN), (short)(tbsCertLen + X509_DER_SIGNATURE.length + signLen));

		return (short)(X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length + signLen);
	}

	private short extractPublicKeyFromCertificate(byte[] cert, short certOffset, short certLen,
												  byte[] outPubKey, short outPubKeyOffset) {
		short pubKeyDerIndex = (short)0;
		for(short i = (short)0; i < certLen; i++) {
			short j = (short)0;
			for(; j < (short)DER_PUB_KEY_OID.length; j++) {
				if(cert[(short)(certOffset + i + j)] != DER_PUB_KEY_OID[j]) {
					break;
				}
			}
			if(j == (short)DER_PUB_KEY_OID.length) {
				for (; j < (short) DER_EC_KEY_CURVE_OID.length; j++) {
					if (cert[(short) (certOffset + i + j)] != DER_EC_KEY_CURVE_OID[j]) {
						break;
					}
				}
			}
			if(j == (short)(DER_PUB_KEY_OID.length + DER_EC_KEY_CURVE_OID.length) && cert[(short)(certOffset + i + j + 1)] == 0x03) {
				pubKeyDerIndex = (short)(i + j + 1);
			}
		}
		if(pubKeyDerIndex > (short)0) {
			return Util.arrayCopyNonAtomic(cert, (short)(certOffset + pubKeyDerIndex), outPubKey, outPubKeyOffset, cert[(short)(certOffset + pubKeyDerIndex + 1)]);
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

		ICUtil.shortArrayFillNonAtomic(keyPairLengthsHolder, (short)0, (short)2, (short)0);
		short keyBlobStart = (short) 0;
		mCryptoManager.createEcKeyPair(tempBuffer, keyBlobStart, keyPairLengthsHolder);
		Util.arrayCopyNonAtomic(tempBuffer, keyBlobStart, ephemeralPrivateKey, (short)0, CryptoManager.EC_KEY_SIZE);

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
			Util.arrayCopyNonAtomic(tempBuffer, challengeOffset, authChallenge, (short) 0, LONG_SIZE);
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
		Util.arrayCopyNonAtomic(readerPublicKey, (short)0, tempBuffer, outPubKeyOffset, pubKeySize);
		readerPublicKeySize[(short)0] = pubKeySize;

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private short processStartRetrieval(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
									   byte[] outBuffer, short le,
									   byte[] tempBuffer) {
		// HAL may use this object multiple times to retrieve data so need to reset various
		// state objects here.
		status[requestMessageValidated] = false;
		status[buildCbor] = false;
		Util.arrayFillNonAtomic(acpMasksInts, accessControlProfileMaskValidatedOffset, INT_SIZE, (byte)0);
		Util.arrayFillNonAtomic(acpMasksInts, accessControlProfileMaskUsesReaderAuthOffset, INT_SIZE, (byte)0);
		Util.arrayFillNonAtomic(acpMasksInts, accessControlProfileMaskFailedReaderAuthOffset, INT_SIZE, (byte)0);
		Util.arrayFillNonAtomic(acpMasksInts, accessControlProfileMaskFailedUserAuthOffset, INT_SIZE, (byte)0);
		readerPublicKeySize[0] = 0;

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private short processSetAuthToken(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
									  byte[] outBuffer, short le,
									  byte[] tempBuffer) {
		byte returnCode = (byte)0;
		Util.arrayFillNonAtomic(tempBuffer, (short)0, LONG_SIZE, (byte)0);
		if(Util.arrayCompare(authChallenge, (short) 0, tempBuffer, (short) 0, LONG_SIZE) == (byte)0) {
			returnCode = (byte)1;
			mCBOREncoder.init(outBuffer, (short) 0, le);
			mCBOREncoder.startArray((short)1);
			mCBOREncoder.encodeUInt8((byte)returnCode); //Error
			return mCBOREncoder.getCurrentOffset();
		}
		mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		byte intSize = mCBORDecoder.getIntegerSize();
		if (intSize < LONG_SIZE) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short challengeOffset = (short)0;
		mCBORDecoder.readInt64(tempBuffer, challengeOffset);
		if(Util.arrayCompare(tempBuffer, challengeOffset, authChallenge, (short)0, LONG_SIZE) != 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		if(!validateAuthToken(receiveBuffer, receivingDataOffset, receivingDataLength, tempBuffer)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
//		authAndVerificationTokensLongs, authTokenChallengeOffset

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		return mCBOREncoder.getCurrentOffset();
	}

	private boolean validateAuthToken(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength, byte[] tempBuffer) {
		// Here's where we would validate the passed-in |authToken| to assure ourselves
		// that it comes from the e.g. biometric hardware and wasn't made up by an attacker.
		//
		// However this involves calculating the MAC which requires access to the to
		// a pre-shared key which we don't have...
		//
		return true;
	}
}
