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

    private final short[] keyPairLengthsHolder;
    
	public JCICPresentation(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
		proofOfProvisioningSha256 = JCSystem.makeTransientByteArray(CryptoManager.SHA256_DIGEST_SIZE, JCSystem.CLEAR_ON_RESET);
		keyPairLengthsHolder = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);
	}

	public void reset() {

	}

	public void processAPDU() {
		mAPDUManager.receiveAll();
		byte[] buf = mAPDUManager.getReceiveBuffer();

		switch(buf[ISO7816.OFFSET_INS]) {
			case ISO7816.INS_ICS_PRESENTATION_INIT:
				processPresentationInit();
			case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY_PAIR:
			case ISO7816.INS_ICS_CREATE_AUTH_CHALLENGE:
			case ISO7816.INS_ICS_START_RETRIEVAL:
			case ISO7816.INS_ICS_SET_AUTH_TOKEN:
			case ISO7816.INS_ICS_PUSH_READER_CERT:
			case ISO7816.INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES:
			case ISO7816.INS_ICS_VALIDATE_REQUEST_MESSAGE:
			case ISO7816.INS_ICS_CAL_MAC_KEY:
			case ISO7816.INS_ICS_START_RETRIEVE_ENTRY_VALUE:
			case ISO7816.INS_ICS_RETRIEVE_ENTRY_VALUE:
			case ISO7816.INS_ICS_FINISH_RETRIEVAL:
			case ISO7816.INS_ICS_GENERATE_SIGNING_KEY_PAIR:
				processGenerateSingingKeyPair();
			case ISO7816.INS_ICS_PROVE_OWNERSHIP:
			case ISO7816.INS_ICS_DELETE_CREDENTIAL:
			case ISO7816.INS_ICS_UPDATE_CREDENTIAL:
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void processPresentationInit() {
		reset();
		byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();

		boolean isTestCredential = Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1;
		byte[] tempBuffer = mCryptoManager.getTempBuffer();

		//If P1P2 other than 0000 and 0001 throw exception
		if(!isTestCredential && Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
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
		mCryptoManager.decryptCredentialData(isTestCredential,
				tempBuffer, (short)(encryptedCredentialKeyOff + CryptoManager.AES_GCM_IV_SIZE), (short)(encryptedCredentialKeysSize - (CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE)),
				tempBuffer, outDataOffset,
				tempBuffer, encryptedCredentialKeyOff, CryptoManager.AES_GCM_IV_SIZE,
				tempBuffer, docTypeOffset, docTypeLength,
				tempBuffer, (short)(encryptedCredentialKeyOff + encryptedCredentialKeysSize - CryptoManager.AES_GCM_TAG_SIZE), CryptoManager.AES_GCM_TAG_SIZE);


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

		short le = mAPDUManager.setOutgoing();
		byte[] outBuffer = mAPDUManager.getSendBuffer();
		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)1);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
	}
	void processGenerateSingingKeyPair() {
		byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
		short le = mAPDUManager.setOutgoing(true);
		byte[] outBuffer = mAPDUManager.getSendBuffer();

		boolean isTestCredential = Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1;
		byte[] tempBuffer = mCryptoManager.getTempBuffer();

		//If P1P2 other than 0000 and 0001 throw exception
		if(!isTestCredential && Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
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

		short proofOfBindingStart = mCBORDecoder.getCurrentOffset();
		mCBOREncoder.init(tempBuffer, (short) proofOfBindingStart, (short)60); //if cbor encoding size is greater than 60 exception will be thrown
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeTextString(STR_PROOF_OF_BINDING, (short)0, (short)STR_PROOF_OF_BINDING.length);
		mCBOREncoder.encodeByteString(proofOfProvisioningSha256, (short)0, CryptoManager.SHA256_DIGEST_SIZE);

		short keyBlobStart = mCBOREncoder.getCurrentOffset();
		mCryptoManager.createEcKeyPair(tempBuffer, keyBlobStart, keyPairLengthsHolder);

		mCBOREncoder.init(outBuffer, (short) 0, le);
		mCBOREncoder.startArray((short)2);
		mCBOREncoder.encodeUInt8((byte)0); //Success
		mCBOREncoder.startArray((short)2);//TODO add certificate and signing key blob

		//TODO generate public key certificate and encode in outBuffer

		mCBOREncoder.startByteString((short) (CryptoManager.AES_GCM_IV_SIZE + CryptoManager.EC_KEY_SIZE + CryptoManager.AES_GCM_TAG_SIZE));
		short encOutOffset = (short)(keyBlobStart + CryptoManager.EC_KEY_SIZE);
		mCryptoManager.aesGCMEncrypt(tempBuffer, keyBlobStart, CryptoManager.EC_KEY_SIZE, //signing private key as input data
				tempBuffer, encOutOffset, //public key is no more required so overriding it
				tempBuffer, docTypeOffset, docTypeLength,
				tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS);
		Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS, outBuffer, mCBOREncoder.getCurrentOffset(), CryptoManager.AES_GCM_IV_SIZE);
		Util.arrayCopyNonAtomic(tempBuffer, encOutOffset, outBuffer, (short)(mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE), CryptoManager.EC_KEY_SIZE);
		Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_GCM_TAG_POS, outBuffer, (short) (mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE + CryptoManager.EC_KEY_SIZE), CryptoManager.AES_GCM_TAG_SIZE);

		mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
	}
}
