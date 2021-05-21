package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

import static android.security.jcic.ICConstants.*;

/**
 * A class to handle all provisioning related operations
 * with the help of CryptoManager and CBOR encoder and decoder.
 *
 */
final class JCICProvisioning {
	// Reference to internal Crypto Manager instance
	private CryptoManager mCryptoManager;
	
    // Reference to the internal APDU manager instance
    private final APDUManager mAPDUManager;
    
    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;

    
    // Digester object for calculating provisioned data digest 
    private final MessageDigest mDigest;

    // Digester object for calculating proof of provisioning data digest 
    private final MessageDigest mSecondaryDigest;
    
    // Digester object for calculating addition data digest 
    private final MessageDigest mAdditionalDataDigester;
    
    private final short[] mEntryCounts;

    private final byte[] mIntExpectedCborSizeAtEnd;
    private final byte[] mIntCurrentCborSize;
    private final byte[] mIntCurrentEntrySize;
    private final byte[] mIntCurrentEntryNumBytesReceived;

    private final byte[] mAdditionalDataSha256;

    private final short[] mStatusWords;

	public JCICProvisioning(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
        
        mEntryCounts = JCSystem.makeTransientShortArray(MAX_NUM_NAMESPACES, JCSystem.CLEAR_ON_DESELECT);
        mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);

        mAdditionalDataSha256 = JCSystem.makeTransientByteArray(CryptoManager.SHA256_DIGEST_SIZE, JCSystem.CLEAR_ON_DESELECT);

        mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mSecondaryDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mAdditionalDataDigester = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        
        mIntExpectedCborSizeAtEnd = JCSystem.makeTransientByteArray((short) INT_SIZE, JCSystem.CLEAR_ON_RESET);
        mIntCurrentCborSize = JCSystem.makeTransientByteArray((short) (INT_SIZE + SHORT_SIZE), JCSystem.CLEAR_ON_RESET);
        mIntCurrentEntrySize = JCSystem.makeTransientByteArray((short) INT_SIZE, JCSystem.CLEAR_ON_RESET);
        mIntCurrentEntryNumBytesReceived = JCSystem.makeTransientByteArray((short) (INT_SIZE + SHORT_SIZE), JCSystem.CLEAR_ON_RESET);
	}

	public void reset() {
	    Util.arrayFillNonAtomic(mIntExpectedCborSizeAtEnd, (short)0, (short) INT_SIZE, (byte)0);
	    Util.arrayFillNonAtomic(mIntCurrentCborSize, (short)0, (short)(INT_SIZE + SHORT_SIZE), (byte)0);
	    Util.arrayFillNonAtomic(mIntCurrentEntrySize, (short)0, (short) INT_SIZE, (byte)0);
	    Util.arrayFillNonAtomic(mIntCurrentEntryNumBytesReceived, (short)0, (short)(INT_SIZE + SHORT_SIZE), (byte)0);
        Util.arrayFillNonAtomic(mAdditionalDataSha256, (short)0, CryptoManager.SHA256_DIGEST_SIZE, (byte)0);

        mDigest.reset();
	    mSecondaryDigest.reset();
	    mAdditionalDataDigester.reset();
	    
        ICUtil.shortArrayFillNonAtomic(mEntryCounts, (short) 0, MAX_NUM_NAMESPACES, (short) 0);
        ICUtil.shortArrayFillNonAtomic(mStatusWords, (short) 0, STATUS_WORDS, (short) 0);
	}
	
	private void updatePrimaryDigest(byte[] data, short dataStart, short dataLen) {
		mDigest.update(data, dataStart, dataLen);

		Util.setShort(mIntCurrentCborSize, (short) INT_SIZE, dataLen);
		ICUtil.incrementByteArray(mIntCurrentCborSize, (short)0, INT_SIZE, mIntCurrentCborSize, (short) INT_SIZE, SHORT_SIZE);
	}
	private void updatePrimaryAndSecondaryDigest(byte[] data, short dataStart, short dataLen) {
		updatePrimaryDigest(data, dataStart, dataLen);
		mSecondaryDigest.update(data, dataStart, dataLen);
	}

	public void processAPDU() {
        mAPDUManager.receiveAll();
        byte[] buf = mAPDUManager.getReceiveBuffer();

        switch(buf[ISO7816.OFFSET_INS]) {
	        case ISO7816.INS_ICS_PROVISIONING_INIT:
                processProvisioningInit();
	            break;
	        case ISO7816.INS_ICS_CREATE_CREDENTIAL_KEY:
	            //TODO need to create Remote Key Provisioning API
                processCreateCredentialKey();
	            break;
	        case ISO7816.INS_ICS_START_PERSONALIZATION:
	        	processStartPersonalization();
	            break;
	        case ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE:
	        	processAddAccessControlProfile();
	            break;
	        case ISO7816.INS_ICS_BEGIN_ADD_ENTRY:
	        	processBeginAddEntry();
	            break;
	        case ISO7816.INS_ICS_ADD_ENTRY_VALUE:
	        	processAddEntryValue();
	            break;
	        case ISO7816.INS_ICS_FINISH_ADDING_ENTRIES:
	        	processFinishAddingEntries();
	            break;
	        case ISO7816.INS_ICS_FINISH_GET_CREDENTIAL_DATA:
	        	processFinishGetCredentialData();
	            break;
	        default: 
	            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
	}

    private void processProvisioningInit() {
        reset();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();

        boolean isTestCredential = Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1;
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL, isTestCredential);

        //If P1P2 other than 0000 and 0001 throw exception
        if(!isTestCredential && Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        mCryptoManager.createCredentialStorageKey(isTestCredential);

        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_PERSONALIZATION_STATE, false);
        // Credential keys are loaded
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_KEYS_INITIALIZED, true);

        short le = mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
    }

	private void processCreateCredentialKey() {
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        byte[] tempBuffer = mCryptoManager.getTempBuffer();

        //If P1P2 other than 0000 and 0001 throw exception
        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        mCryptoManager.createEcKeyPairAndAttestation(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL));
        short pubKeyLen = mCryptoManager.getCredentialEcPubKey(tempBuffer, (short)0);

        short le = mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeByteString(tempBuffer, (short)0, pubKeyLen);
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
	}
	
	private void processStartPersonalization() {
        mCryptoManager.assertCredentialInitialized();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZATION_STATE);
        byte[] tempBuffer = mCryptoManager.getTempBuffer();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();

        short le = mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

        // hold a docType in temp buffer
        short docTypeLength = mCBORDecoder.readByteString(tempBuffer, (short)0);

        short accessControlProfileCount = mCBORDecoder.readInt8();
        if(accessControlProfileCount >= MAX_NUM_ACCESS_CONTROL_PROFILE_IDS) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short numEntryCounts = mCBORDecoder.readLength();
        if(numEntryCounts >= MAX_NUM_NAMESPACES) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        mStatusWords[STATUS_NUM_ENTRY_COUNTS] = numEntryCounts;
        //Check each entry count should not exceed 255 and preserve entry counts
        for(short i = 0; i < numEntryCounts; i++) {
        	short entryCount = 0;
        	byte intSize = mCBORDecoder.getIntegerSize();
	        if(intSize  == BYTE_SIZE) {
	        	//One byte integer = max 255
	        	entryCount = mCBORDecoder.readInt8();
	        	mEntryCounts[i] = entryCount;
	        } else {
	        	//Entry count should not exceed 255
	        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	        }
        }
        
        mStatusWords[STATUS_CURRENT_NAMESPACE] = (short) -1;
        mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;


        // What we're going to sign is the COSE ToBeSigned structure which
        // looks like the following:
        //
        // Sig_structure = [
        //   context : "Signature" / "Signature1" / "CounterSignature",
        //   body_protected : empty_or_serialized_map,
        //   ? sign_protected : empty_or_serialized_map,
        //   external_aad : bstr,
        //   payload : bstr
        //  ]
        //
        mDigest.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short) 4);
        mCBOREncoder.encodeTextString(STR_SIGNATURE1, (short) 0, (short) STR_SIGNATURE1.length);
        // The COSE Encoded protected headers is just a single field with
        // COSE_LABEL_ALG (1) -> COSE_ALG_ECSDA_256 (-7). For simplicitly we just
        // hard-code the CBOR encoding:
        mCBOREncoder.encodeByteString(COSE_ENCODED_PROTECTED_HEADERS_ECDSA, (short) 0, (short) COSE_ENCODED_PROTECTED_HEADERS_ECDSA.length);
        // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
        // so external_aad is the empty bstr
        mCBOREncoder.encodeByteString(tempBuffer, (short)0, (short)0); // byte string of 0 length
        // For the payload, the _encoded_ form follows here. We handle this by simply
        // opening a bstr, and then writing the CBOR. This requires us to know the
        // size of said bstr, ahead of time.
        // Encode byteString of received length (expectedProofOfProvisioningSize) without actual byteString
    	byte intSize = mCBORDecoder.getIntegerSize();
    	if(intSize == BYTE_SIZE) {
    		byte expectedLen = mCBORDecoder.readInt8();
    		mCBOREncoder.startByteString(expectedLen);
    		mIntExpectedCborSizeAtEnd[3] = expectedLen;
    	} else if (intSize == SHORT_SIZE) {
    		short expectedLen = mCBORDecoder.readInt16();
    		mCBOREncoder.startByteString(expectedLen);
    		Util.setShort(mIntExpectedCborSizeAtEnd, (short)2, expectedLen);
    	} else if(intSize == INT_SIZE) {
    		mCBORDecoder.readInt32(tempBuffer, (short)docTypeLength);
    		mCBOREncoder.startByteString(tempBuffer, (short)docTypeLength, intSize);
    		Util.arrayCopyNonAtomic(tempBuffer, (short)docTypeLength, mIntExpectedCborSizeAtEnd, (short) 0, intSize);
    	} else {
    		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    	}
		Util.setShort(tempBuffer, (short)docTypeLength, mCBOREncoder.getCurrentOffset());
		ICUtil.incrementByteArray(mIntExpectedCborSizeAtEnd, (short)0, INT_SIZE, tempBuffer, (short)docTypeLength, SHORT_SIZE);
		updatePrimaryDigest(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
    	mCBOREncoder.reset();
    	// Reseting encoder just to make sure docType should not overflow it
    	mCBOREncoder.init(outBuffer, (short) 0, le);
		
    	mCBOREncoder.startArray((short) 5);
    	mCBOREncoder.encodeTextString(STR_PROOF_OF_PROVISIONING, (short) 0, (short)STR_PROOF_OF_PROVISIONING.length);
        mCBOREncoder.encodeTextString(tempBuffer, (short) 0, docTypeLength);
    	mCBOREncoder.startArray(accessControlProfileCount);
    	
    	updatePrimaryAndSecondaryDigest(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        /* This was added only for testing, we are not going to finalize digest yet.
        mDigest.doFinal(mCryptoManager.getTempBuffer(), (short)0, (short)0, outBuffer, (short)0);
        
        mAPDUManager.setOutgoingLength((short)MessageDigest.LENGTH_SHA_256);*/
        // Set the Applet in the PERSONALIZATION state
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_PERSONALIZATION_STATE, true);

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
    }

	private void processAddAccessControlProfile() {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZING_ENTRIES);
        byte[] tempBuffer = mCryptoManager.getTempBuffer();

        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short le = mAPDUManager.setOutgoing(true); //We need large buffer for CBOR operations
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short outLength = ICUtil.constructCBORAccessControl(mCBORDecoder, mCBOREncoder, receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength(),
        										outBuffer, (short)0, le, true);

        // Calculate and return MAC
        //Encrypt constructed CBOR using AES-GCM and get generated MAC and return it.
        mCryptoManager.aesGCMEncrypt(outBuffer, (short)0, (short)0,
        		tempBuffer, (short) 0,
        		outBuffer, (short)0, outLength,
        		tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS);

        // The ACP CBOR in the provisioning receipt doesn't include secureUserId so build
        // it again.
        outLength = ICUtil.constructCBORAccessControl(mCBORDecoder, mCBOREncoder, receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength(),
        									outBuffer, (short)0, le, false);
        updatePrimaryAndSecondaryDigest(outBuffer, (short)0, outLength);

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeByteString(tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS, (short)(CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE));
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
        //Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS, outBuffer, (short) 0, (short)(CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE));
        //mAPDUManager.setOutgoingLength((short)(CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE));
	}

	private void processBeginAddEntry() {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZING_ENTRIES);
        byte[] tempBuffer = mCryptoManager.getTempBuffer();

        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short le = mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        constAndCalcCBOREntryAdditionalData(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength(),
        		outBuffer, (short)0, le, mAdditionalDataSha256, (short) 0);

        mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        //Hold nameSpace in temp variable
        short nameSpaceLen = mCBORDecoder.readByteString(tempBuffer, (short) 0);
        if(mStatusWords[STATUS_CURRENT_NAMESPACE] == (short)-1) {
        	mStatusWords[STATUS_CURRENT_NAMESPACE] = (short)0;
            mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;
            // Opens the main map: { * Namespace => [ + Entry ] }
            mCBOREncoder.startMap(mStatusWords[STATUS_NUM_ENTRY_COUNTS]);
            //encode nameSpace string
            mCBOREncoder.encodeTextString(tempBuffer, (short)0, nameSpaceLen);
            // Opens the per-namespace array: [ + Entry ]
            mCBOREncoder.startArray(mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]);
        }

        if(mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] == mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]) {
        	mStatusWords[STATUS_CURRENT_NAMESPACE] += (short)1;
        	mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;
            //encode nameSpace string
            mCBOREncoder.encodeTextString(tempBuffer, (short)0, nameSpaceLen);
            // Opens the per-namespace array: [ + Entry ]
            mCBOREncoder.startArray(mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]);
        }
        mCBOREncoder.startMap((short) 3);
        //encode key as name string
        mCBOREncoder.encodeTextString(STR_NAME, (short)0, (short)STR_NAME.length);
        //read name parameter
        short nameLen = mCBORDecoder.readByteString(tempBuffer, (short) 0);
        mCBOREncoder.encodeTextString(tempBuffer, (short) 0, nameLen);
        
        mCBORDecoder.skipEntry();//AccessControlProfileIds
	    Util.arrayFillNonAtomic(mIntCurrentEntrySize, (short)0, (short) INT_SIZE, (byte)0); //Reset currentEntrySize before getting it from parameters
        byte intSize = mCBORDecoder.getIntegerSize();
    	if(intSize == BYTE_SIZE) {
    		byte expectedLen = mCBORDecoder.readInt8();
    		mIntCurrentEntrySize[3] = expectedLen;
    	} else if (intSize == SHORT_SIZE) {
    		short expectedLen = mCBORDecoder.readInt16();
    		Util.setShort(mIntCurrentEntrySize, (short)2, expectedLen);
    	} else if(intSize == INT_SIZE) {
    		mCBORDecoder.readInt32(mIntCurrentEntrySize, (short)0);
    	} else {
    		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    	}
	    Util.arrayFillNonAtomic(mIntCurrentEntryNumBytesReceived, (short)0, (short)(INT_SIZE + SHORT_SIZE), (byte)0);

        //encode key as value string
        mCBOREncoder.encodeTextString(STR_VALUE, (short)0, (short)STR_VALUE.length);

        updatePrimaryAndSecondaryDigest(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
    	
    	mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] += (short) 1;

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
	}

	private short constAndCalcCBOREntryAdditionalData(byte[] inBuff, short inOffset, short inLen,
											byte[] outBuff, short outOffset, short outLen,
											byte[] shaOut, short shaOutOff) {

        byte[] tempBuffer = mCryptoManager.getTempBuffer();
        mCBORDecoder.init(inBuff, inOffset, inLen);
        mCBOREncoder.init(outBuff, outOffset, outLen);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        mCBOREncoder.startMap((short) 3);
        //encode key as Namespace string
        mCBOREncoder.encodeTextString(STR_NAME_SPACE, (short)0, (short)STR_NAME_SPACE.length);
        //Hold nameSpace in temp variable
        short nameSpaceLen = mCBORDecoder.readByteString(tempBuffer, (short) 0);
        //encode nameSpace string
        mCBOREncoder.encodeTextString(tempBuffer, (short)0, nameSpaceLen);
        //encode key as Name string, lets use it from Namespace string
        mCBOREncoder.encodeTextString(STR_NAME_SPACE, (short)0, (short)4);
        //read name parameter
        short nameLen = mCBORDecoder.readByteString(tempBuffer, (short) 0);
        mCBOREncoder.encodeTextString(tempBuffer, (short) 0, nameLen);
        
        //encode key as AccessControlProfileIds string
        mCBOREncoder.encodeTextString(STR_ACCESS_CONTROL_PROFILE_IDS, (short)0, (short)STR_ACCESS_CONTROL_PROFILE_IDS.length);
        short acpIdLen = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        mCBOREncoder.startArray(acpIdLen);
        for(short i = (short)0; i < acpIdLen; i++) {
        	//Util.arrayCopyNonAtomic(inBuff, mCBORDecoder.getCurrentOffset(), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(mCBORDecoder.readLength()), mCBORDecoder.readLength());
        	byte intSize = mCBORDecoder.getIntegerSize();
        	if(intSize == BYTE_SIZE) {
        		mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
        	} else if(intSize == SHORT_SIZE) {
        		mCBOREncoder.encodeUInt16(mCBORDecoder.readInt16());
        	} else {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }
        mAdditionalDataDigester.doFinal(outBuff, outOffset, mCBOREncoder.getCurrentOffset(), shaOut, shaOutOff);
        
        return mCBOREncoder.getCurrentOffset();
	}

	private void processAddEntryValue() {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZING_PROFILES);
        byte[] tempBuffer = mCryptoManager.getTempBuffer();

        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short le = mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short additionalDataLen = constAndCalcCBOREntryAdditionalData(receiveBuffer, mCBORDecoder.getCurrentOffset(), mAPDUManager.getReceivingLength(),
        		outBuffer, (short)0, le, tempBuffer, (short) 0);

        //Compare calculated hash of additional data with preserved hash from addEntry
        if(Util.arrayCompare(tempBuffer, (short) 0, mAdditionalDataSha256, (short) 0, CryptoManager.SHA256_DIGEST_SIZE) != (byte)0) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        //We need to reset decoder
        mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        mCBORDecoder.skipEntry(); //Skip additionalData

        //read content
        short contentLen = mCBORDecoder.readByteString(tempBuffer, (short) 0);
        updatePrimaryAndSecondaryDigest(tempBuffer, (short) 0, contentLen);
        
        if((short)(contentLen * 2) > CryptoManager.TEMP_BUFFER_SIZE) {
        	ISOException.throwIt(ISO7816.SW_INSUFFICIENT_MEMORY);
        }
        //Encrypt content and additional data as aad
        mCryptoManager.aesGCMEncrypt(
        		tempBuffer, (short)0, contentLen, //in data
        		tempBuffer, contentLen, //Out encrypted data
        		outBuffer, (short)0, additionalDataLen, //Auth data
        		tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS); //nonce and tag

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.startByteString((short) (CryptoManager.AES_GCM_IV_SIZE + contentLen + CryptoManager.AES_GCM_TAG_SIZE));
        //Output will be nonce|encryptedData|tag
        Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS, outBuffer, mCBOREncoder.getCurrentOffset(), CryptoManager.AES_GCM_IV_SIZE);
        Util.arrayCopyNonAtomic(tempBuffer, contentLen, outBuffer, (short)(mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE), contentLen);
        Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_GCM_TAG_POS, outBuffer, (short) (mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE + contentLen), CryptoManager.AES_GCM_TAG_SIZE);
        // nonce, encrypted content and tag are already copied to outBuffer
        mAPDUManager.setOutgoingLength((short) (mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE + contentLen + CryptoManager.AES_GCM_TAG_SIZE));

        // If done with this entry, close the map
        Util.setShort(mIntCurrentEntryNumBytesReceived, (short) INT_SIZE, contentLen);
        ICUtil.incrementByteArray(mIntCurrentEntryNumBytesReceived, (short)0, INT_SIZE, mIntCurrentEntryNumBytesReceived, (short) INT_SIZE, SHORT_SIZE);
        if(Util.arrayCompare(mIntCurrentEntryNumBytesReceived, (short) 0, mIntCurrentEntrySize, (short) 0, INT_SIZE) == 0) {
            //We need to reset decoder and encoder
            mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        	mCBOREncoder.init(tempBuffer, (short) 0, CryptoManager.TEMP_BUFFER_SIZE);
        	
        	mCBOREncoder.encodeTextString(STR_ACCESS_CONTROL_PROFILES, (short)0, (short)STR_ACCESS_CONTROL_PROFILES.length);
            mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
            //Get Additional
            mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
            mCBORDecoder.skipEntry(); //NameSpace
            mCBORDecoder.skipEntry(); //Name
            short acpIdLen = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY); //ACP Ids count
            mCBOREncoder.startArray(acpIdLen);
            for(short i = (short)0; i < acpIdLen; i++) {
            	byte intSize = mCBORDecoder.getIntegerSize();
            	if(intSize == BYTE_SIZE) {
            		mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
            	} else if(intSize == SHORT_SIZE) {
            		mCBOREncoder.encodeUInt16(mCBORDecoder.readInt16());
            	} else {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
            }
            updatePrimaryAndSecondaryDigest(tempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        }
	}

	private void processFinishAddingEntries() {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZING_PROFILES);
        byte[] tempBuffer = mCryptoManager.getTempBuffer();

        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short le = mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mCBOREncoder.init(tempBuffer, (short) 0, CryptoManager.TEMP_BUFFER_SIZE);
        mCBOREncoder.encodeBoolean(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL));
        updatePrimaryAndSecondaryDigest(tempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        mDigest.doFinal(tempBuffer, (short) 0, (short)0, tempBuffer, mCBOREncoder.getCurrentOffset());

        // This verifies that the correct expectedProofOfProvisioningSize value was
        // passed in at eicStartPersonalization() time.
        byte comp = Util.arrayCompare(mIntExpectedCborSizeAtEnd, (short)0, mIntCurrentCborSize, (short)0, (short) INT_SIZE);
        if(comp != 0) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short signLen = mCryptoManager.ecSignWithNoDigest(tempBuffer, mCBOREncoder.getCurrentOffset(), outBuffer, (short) 0);
        Util.arrayCopyNonAtomic(outBuffer, (short) 0, tempBuffer, (short)0, signLen);
        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeByteString(tempBuffer, (short)0, signLen);
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
	}

	private void processFinishGetCredentialData() {
        byte[] tempBuffer = mCryptoManager.getTempBuffer();

        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short le = mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        mCBOREncoder.init(outBuffer, (short) 0, le);
        
		mCBOREncoder.startArray((short)3);
		mCryptoManager.getCredentialStorageKey(tempBuffer, (short) 0);
		mCBOREncoder.encodeByteString(tempBuffer, (short) 0, CryptoManager.AES_GCM_KEY_SIZE);
		mCryptoManager.getCredentialEcKey(tempBuffer, (short) 0);
		mCBOREncoder.encodeByteString(tempBuffer, (short) 0, CryptoManager.EC_KEY_SIZE);
		mSecondaryDigest.doFinal(tempBuffer, (short)0, (short) 0, tempBuffer, (short)0); //Data is of 0 size and collect digest in tempBuffer
		mCBOREncoder.encodeByteString(tempBuffer, (short) 0, CryptoManager.SHA256_DIGEST_SIZE);
		
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short docTypeLen = mCBORDecoder.readByteString(tempBuffer, (short)0);
		short dataSize = mCBOREncoder.getCurrentOffset();
		mCryptoManager.entryptCredentialData(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL),
				outBuffer, (short) 0, mCBOREncoder.getCurrentOffset(), //in data
				tempBuffer, (short) 0, //out encrypted data
				tempBuffer, (short) 0, docTypeLen, //Auth data
				tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS); //Nonce and tag

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.startByteString((short)(CryptoManager.AES_GCM_IV_SIZE + dataSize + CryptoManager.AES_GCM_TAG_SIZE));
        //Output will be nonce|encryptedData|tag
        Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_IV_POS, outBuffer, mCBOREncoder.getCurrentOffset(), CryptoManager.AES_GCM_IV_SIZE);
        Util.arrayCopyNonAtomic(tempBuffer, (short) 0, outBuffer, (short) (mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE), dataSize);
        Util.arrayCopyNonAtomic(tempBuffer, CryptoManager.TEMP_BUFFER_GCM_TAG_POS, outBuffer, (short) (mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE + dataSize), CryptoManager.AES_GCM_TAG_SIZE);
        mAPDUManager.setOutgoingLength((short)(mCBOREncoder.getCurrentOffset() + CryptoManager.AES_GCM_IV_SIZE + dataSize + CryptoManager.AES_GCM_TAG_SIZE));
	}
}
