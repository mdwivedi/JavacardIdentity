package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * A class to handle all provisioning related operations
 * with the help of CryptoManager and CBOR encoder and decoder.
 *
 */
public class JCICProvisioning {
	private static final short MAX_NUM_ACCESS_CONTROL_PROFILE_IDS = 32;
    private static final short MAX_NUM_NAMESPACES = 32;
    
    public static final byte STATUS_NUM_ENTRY_COUNTS = 0;
    public static final byte STATUS_CURRENT_NAMESPACE = 1;
    public static final byte STATUS_CURRENT_NAMESPACE_NUM_PROCESSED = 2;
    public static final byte STATUS_CURRENT_ENTRY_SIZE = 3;
    public static final byte STATUS_CURRENT_ENTRY_NUM_BYTES_RECEIVED = 4;
    public static final byte STATUS_EXPECTED_CBOR_SIZE_AT_END = 5;
    private static final byte STATUS_WORDS = 6;
    
    //Signature1
    private static final byte[] STR_SIGNATURE1 = new byte[] {(byte)0x53, (byte)0x69, (byte)0x67, (byte)0x6E, (byte)0x61,
															(byte)0x74, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x31};
    //ProofOfProvisioning
    private static final byte[] STR_PROOF_OF_PROVISIONING = new byte[] {(byte)0x50, (byte)0x72, (byte)0x6f, (byte)0x6f,
    														(byte)0x66, (byte)0x4f, (byte)0x66, (byte)0x50, (byte)0x72,
    														(byte)0x6f, (byte)0x76, (byte)0x69, (byte)0x73, (byte)0x69,
    														(byte)0x6f, (byte)0x6e, (byte)0x69, (byte)0x6e, (byte)0x67};
    //id
    private static final byte[] STR_ID = new byte[] {(byte)0x69, (byte)0x64};
    //readerCertificate
    private static final byte[] STR_READER_CERTIFICATE = new byte[] {(byte)0x72, (byte)0x65, (byte)0x61, (byte)0x64,
    														(byte)0x65, (byte)0x72, (byte)0x43, (byte)0x65, (byte)0x72,
    														(byte)0x74, (byte)0x69, (byte)0x66, (byte)0x69, (byte)0x63,
    														(byte)0x61, (byte)0x74, (byte)0x65};
    //userAuthenticationRequired
    private static final byte[] STR_USER_AUTH_REQUIRED = new byte[] {(byte)0x75, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x41,
    													(byte)0x75, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x6e, (byte)0x74,
    													(byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f,
    													(byte)0x6e, (byte)0x52, (byte)0x65, (byte)0x71, (byte)0x75, (byte)0x69,
    													(byte)0x72, (byte)0x65, (byte)0x64};
    //timeoutMillis
    private static final byte[] STR_TIMEOUT_MILIS = new byte[] {(byte)0x74, (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x6f,
    												(byte)0x75, (byte)0x74, (byte)0x4d, (byte)0x69, (byte)0x6c, (byte)0x6c,
    												(byte)0x69, (byte)0x73};
    //secureUserId
    private static final byte[] STR_SECURE_USER_ID = new byte[] {(byte)0x73, (byte)0x65, (byte)0x63, (byte)0x75, (byte)0x72,
    												(byte)0x65, (byte)0x55, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x49,
    												(byte)0x64};
    //name
    private static final byte[] STR_NAME = {(byte) 0x6e, (byte) 0x61, (byte) 0x6d, (byte) 0x65};
    //value
    private static final byte[] STR_VALUE = {(byte) 0x76, (byte) 0x61, (byte) 0x6c, (byte) 0x75, (byte) 0x65};
    //Namespace
    private static final byte[] STR_NAME_SPACE = {(byte) 0x4e, (byte) 0x61, (byte) 0x6d, (byte) 0x65, (byte) 0x73, (byte) 0x70, (byte) 0x61, (byte) 0x63, (byte) 0x65};
    //AccessControlProfileIds
    private static final byte[] STR_ACCESS_CONTROL_PROFILE_IDS = {(byte) 0x41, (byte) 0x63, (byte) 0x63, (byte) 0x65,
    												(byte) 0x73, (byte) 0x73, (byte) 0x43, (byte) 0x6f, (byte) 0x6e,
    												(byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6c, (byte) 0x50,
    												(byte) 0x72, (byte) 0x6f, (byte) 0x66, (byte) 0x69, (byte) 0x6c,
    												(byte) 0x65, (byte) 0x49, (byte) 0x64, (byte) 0x73};
    
    private static final byte[] COSE_ENCODED_PROTECTED_HEADERS = {(byte) 0xa1, (byte)0x01, (byte)0x26};
    
    
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
    
    // Digester object for calculating addition data digest 
    private final MessageDigest mAdditionalDataDigester;
    
    private final short[] mEntryCounts;
    
    private final byte[] mAdditionalDataSha256;

    private final short[] mStatusWords;

	public JCICProvisioning(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
        
        mEntryCounts = JCSystem.makeTransientShortArray(MAX_NUM_NAMESPACES, JCSystem.CLEAR_ON_DESELECT);
        mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);

        mAdditionalDataSha256 = JCSystem.makeTransientByteArray(CryptoManager.DIGEST_SIZE, JCSystem.CLEAR_ON_DESELECT);

        mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mAdditionalDataDigester = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

	}

	public void reset() {
		mCryptoManager.reset();
		mAPDUManager.reset();
        ICUtil.shortArrayFillNonAtomic(mEntryCounts, (short) 0, MAX_NUM_NAMESPACES, (short) 0);
        
        ICUtil.shortArrayFillNonAtomic(mStatusWords, (short) 0, STATUS_WORDS, (short) 0);
	}

	public void processAPDU() {
        byte[] buf = mAPDUManager.getReceiveBuffer();

        switch(buf[ISO7816.OFFSET_INS]) {
	        case ISO7816.INS_ICS_CREATE_CREDENTIAL:
	            processCreateCredential();
	            break;
	        case ISO7816.INS_ICS_GET_ATTESTATION_CERT:
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
	        case ISO7816.INS_ICS_BEGIN_ADD_ENTRY_VALUE:
	            break;
	        case ISO7816.INS_ICS_FINISH_ADDING_ENTRIES:
	            break;
	        case ISO7816.INS_ICS_FINISH_GET_CREDENTIAL_DATA:
	            break;
	        default: 
	            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
	}

	private void processCreateCredential() {
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        byte[] tempBuffer = mCryptoManager.getTempBuffer();
        
        // Check if it is a test credential
        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1) { // Test credential
        	mCryptoManager.setStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL, true);
        	Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short)(CryptoManager.getAESKeySize() / 8), (byte)0x00);
	        mCryptoManager.getCredentialStorageKey().setKey(tempBuffer, (short) 0);
        } else if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        } else {        
	        // Generate the AES-128 storage key 
	        mCryptoManager.generateRandomData(tempBuffer, (short) 0, CryptoManager.AES_GCM_KEY_SIZE);
	        mCryptoManager.getCredentialStorageKey().setKey(tempBuffer, (short) 0);
        }

        // Credential keys are loaded
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_KEYS_INITIALIZED, true);
	}
	
	private void processStartPersonalization() {
        mCryptoManager.assertCredentialInitialized();

        mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();

        short le = mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        mCBORDecoder.init(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

        // hold a docType in temp buffer
        short docTypeLength = mCBORDecoder.readByteString(mCryptoManager.getTempBuffer(), (short)0);

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
	        if(intSize  == 1) {
	        	//One byte integer = max 255
	        	entryCount = mCBORDecoder.readInt8();
	        	mEntryCounts[i] = entryCount;
	        } else if(intSize == 2) {
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
        mCBOREncoder.encodeByteString(COSE_ENCODED_PROTECTED_HEADERS, (short) 0, (short) COSE_ENCODED_PROTECTED_HEADERS.length);
        // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
        // so external_aad is the empty bstr
        mCBOREncoder.encodeByteString(mCryptoManager.getTempBuffer(), (short)0, (short)0); // byte string of 0 length
        // For the payload, the _encoded_ form follows here. We handle this by simply
        // opening a bstr, and then writing the CBOR. This requires us to know the
        // size of said bstr, ahead of time.
        // Encode byteString of received length (expectedProofOfProvisioningSize) without actual byteString
    	byte intSize = mCBORDecoder.getIntegerSize();
    	if(intSize == 1) {
    		mCBOREncoder.startByteString(mCBORDecoder.readInt8());
    	} else if (intSize == 2) {
    		//outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_TWO_BYTES;
    		//Util.arrayCopyNonAtomic(receiveBuffer, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuffer, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
    		mCBOREncoder.startByteString(mCBORDecoder.readInt16());
    	} else if(intSize == 4) {
    		//outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_FOUR_BYTES;
    		//Util.arrayCopyNonAtomic(receiveBuffer, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuffer, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
    		mCBORDecoder.readInt32(mCryptoManager.getTempBuffer(), (short)docTypeLength);
    		mCBOREncoder.startByteString(intSize, mCryptoManager.getTempBuffer(), (short)docTypeLength);
    	}
    	mCBOREncoder.startArray((short) 5);
    	mCBOREncoder.encodeTextString(STR_PROOF_OF_PROVISIONING, (short) 0, (short)STR_PROOF_OF_PROVISIONING.length);
    	mDigest.update(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
    	mCBOREncoder.reset();
    	// We are reseting encoder just to make sure docType should not overflow it
    	mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.encodeTextString(mCryptoManager.getTempBuffer(), (short) 0, docTypeLength);
    	mCBOREncoder.startArray(accessControlProfileCount);
    	
        mDigest.update(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        /* This was added only for testing, we are not going to finalize digest yet.
        mDigest.doFinal(mCryptoManager.getTempBuffer(), (short)0, (short)0, outBuffer, (short)0);
        
        mAPDUManager.setOutgoingLength((short)MessageDigest.LENGTH_SHA_256);*/
        // Set the Applet in the PERSONALIZATION state
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_PERSONALIZATION_STATE, true);
		
	}

	private void processAddAccessControlProfile() {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZING_ENTRIES);

        mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short le = mAPDUManager.setOutgoing(true); //We need large buffer for CBOR operations
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short outLength = constructCBORAccessControl(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength(),
        										outBuffer, (short)0, le, true);

        // Calculate and return MAC
        //Encrypt constructed CBOR using AES-GCM and get generated MAC and return it.
        mCryptoManager.aesGCMEncrypt(outBuffer, (short)0, (short)0,
        		mCryptoManager.getTempBuffer(), (short) 0,
        		outBuffer, (short)0, outLength,
        		mCryptoManager.getTempBuffer(), CryptoManager.TEMP_BUFFER_IV_POS);

        // The ACP CBOR in the provisioning receipt doesn't include secureUserId so build
        // it again.
        outLength = constructCBORAccessControl(receiveBuffer, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength(),
        									outBuffer, (short)0, le, false);
        mDigest.update(outBuffer, (short)0, outLength);
        
        Util.arrayCopyNonAtomic(mCryptoManager.getTempBuffer(), CryptoManager.TEMP_BUFFER_IV_POS, outBuffer, (short) 0, (short)(CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE));

        mAPDUManager.setOutgoingLength((short)(CryptoManager.AES_GCM_IV_SIZE + CryptoManager.AES_GCM_TAG_SIZE));
	}
	
	private short constructCBORAccessControl(byte[] inBuff, short inOffset, short inLen,
											byte[] outBuff, short outOffset, short outLen,
											boolean withSecureUserId) {
		short numPairs = (short) 1;


        mCBORDecoder.init(inBuff, inOffset, inLen);
        mCBOREncoder.init(outBuff, outOffset, outLen);
        
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short id = mCBORDecoder.readInt8();
        boolean userAuthRequired = mCBORDecoder.readBoolean();
        mCBORDecoder.skipEntry(); //TimeoutMilis
        boolean secureUserIdPresent = false;
        if(userAuthRequired) {
        	numPairs += 2;
        	if(withSecureUserId) {
	        	byte intSize = mCBORDecoder.getIntegerSize();
	        	if(intSize == 1) {
	        		short secureUserId = mCBORDecoder.readInt8();
	        		if(secureUserId > (short)0) {
	        			secureUserIdPresent = true;
	                	numPairs += 1;
	        		}
	        	} else {
	        		mCBORDecoder.skipEntry();
	        		secureUserIdPresent = true;
	            	numPairs += 1;
	        	}
        	} else {
        		mCBORDecoder.skipEntry();
        	}
        } else {
    		mCBORDecoder.skipEntry();
    	}
        short readerCertSize = mCBORDecoder.readLength();
        if(readerCertSize > (short)0) {
        	numPairs += 1;
        }
        mCBOREncoder.startMap(numPairs);
        mCBOREncoder.encodeTextString(STR_ID, (short)0, (short)STR_ID.length);
        if(id < (short)256) {
            mCBOREncoder.encodeUInt8((byte)id);
        } else {
        	mCBOREncoder.encodeUInt16((short)id);
        }
        if(readerCertSize > (short)0) {
	        //We have already traversed up to readerCertificate, so encode it from decoder
	        mCBOREncoder.encodeTextString(STR_READER_CERTIFICATE, (short)0, (short)STR_READER_CERTIFICATE.length);
	        //mCBORDecoder.readByteString(outBuffer, mCBOREncoder.getCurrentOffset());
	        short encodeReaderCertOffset = mCBOREncoder.startByteString(readerCertSize);
	        Util.arrayCopyNonAtomic(mCBORDecoder.getBuffer(), mCBORDecoder.getCurrentOffset(), outBuff, encodeReaderCertOffset, readerCertSize);
	        mCBOREncoder.increaseOffset(readerCertSize);
        }
        mCBORDecoder.reset();
        //Lets init decoder again to read timeoutMilis and secureUserId
        mCBORDecoder.init(inBuff, inOffset, inLen);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
    	mCBORDecoder.skipEntry();//id
    	userAuthRequired = mCBORDecoder.readBoolean();//userAuthRequired
        if(userAuthRequired) {
        	mCBOREncoder.encodeTextString(STR_USER_AUTH_REQUIRED, (short)0, (short)STR_USER_AUTH_REQUIRED.length);
        	mCBOREncoder.encodeBoolean(userAuthRequired);
        	mCBOREncoder.encodeTextString(STR_TIMEOUT_MILIS, (short)0, (short)STR_TIMEOUT_MILIS.length);
        	byte intSize = mCBORDecoder.getIntegerSize();
        	if(intSize == 1) {
        		//outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
        		mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
        	} else if (intSize == 2) {
        		outBuff[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_TWO_BYTES;
        		Util.arrayCopyNonAtomic(inBuff, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
        	} else if(intSize == 4) {
        		outBuff[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_FOUR_BYTES;
        		Util.arrayCopyNonAtomic(inBuff, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
        	} else if(intSize == 8) {
        		outBuff[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_EIGHT_BYTES;
        		Util.arrayCopyNonAtomic(inBuff, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
        	}
        	
        	if(withSecureUserId && secureUserIdPresent) {
        		mCBOREncoder.encodeTextString(STR_SECURE_USER_ID, (short)0, (short)STR_SECURE_USER_ID.length);
        		intSize = mCBORDecoder.getIntegerSize();
            	if(intSize == 1) {
            		//outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
            		mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
            	} else if (intSize == 2) {
            		outBuff[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_TWO_BYTES;
            		Util.arrayCopyNonAtomic(inBuff, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            	} else if(intSize == 4) {
            		outBuff[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_FOUR_BYTES;
            		Util.arrayCopyNonAtomic(inBuff, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            	} else if(intSize == 8) {
            		outBuff[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_EIGHT_BYTES;
            		Util.arrayCopyNonAtomic(inBuff, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            	}
        	} else {
        		mCBORDecoder.skipEntry();
        	}
        }
        
        return mCBOREncoder.getCurrentOffset();
	}

	private void processBeginAddEntry() {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_CREDENIAL_PERSONALIZING_ENTRIES);

        mAPDUManager.receiveAll();
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
        short nameSpaceLen = mCBORDecoder.readByteString(mCryptoManager.getTempBuffer(), (short) 0);
        if(mStatusWords[STATUS_CURRENT_NAMESPACE] == (short)-1) {
        	mStatusWords[STATUS_CURRENT_NAMESPACE] = (short)0;
            mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;
            // Opens the main map: { * Namespace => [ + Entry ] }
            mCBOREncoder.startMap(mStatusWords[STATUS_NUM_ENTRY_COUNTS]);
            //encode nameSpace string
            mCBOREncoder.encodeTextString(mCryptoManager.getTempBuffer(), (short)0, nameSpaceLen);
            // Opens the per-namespace array: [ + Entry ]
            mCBOREncoder.startArray(mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]);
        }

        if(mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] == mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]) {
        	mStatusWords[STATUS_CURRENT_NAMESPACE] += (short)1;
        	mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;
            //encode nameSpace string
            mCBOREncoder.encodeTextString(mCryptoManager.getTempBuffer(), (short)0, nameSpaceLen);
            // Opens the per-namespace array: [ + Entry ]
            mCBOREncoder.startArray(mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]);
        }
        mCBOREncoder.startMap((short) 3);
        //encode key as name string
        mCBOREncoder.encodeTextString(STR_NAME, (short)0, (short)STR_NAME.length);
        //read name parameter
        short nameLen = mCBORDecoder.readByteString(mCryptoManager.getTempBuffer(), (short) 0);
        mCBOREncoder.encodeTextString(mCryptoManager.getTempBuffer(), (short) 0, nameLen);
        
        if(mCBORDecoder.getIntegerSize() == (short)1) {
        	mStatusWords[STATUS_CURRENT_ENTRY_SIZE] = mCBORDecoder.readInt8();
        } else if(mCBORDecoder.getIntegerSize() == (short)2) {
        	mStatusWords[STATUS_CURRENT_ENTRY_SIZE] = mCBORDecoder.readInt16();
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        mStatusWords[STATUS_CURRENT_ENTRY_NUM_BYTES_RECEIVED] = (short)0;

        //encode key as value string
        mCBOREncoder.encodeTextString(STR_VALUE, (short)0, (short)STR_VALUE.length);

    	mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] += (short) 1;
	}

	private short constAndCalcCBOREntryAdditionalData(byte[] inBuff, short inOffset, short inLen,
											byte[] outBuff, short outOffset, short outLen,
											byte[] shaOut, short shaOutOff) {

        mCBORDecoder.init(inBuff, inOffset, inLen);
        mCBOREncoder.init(outBuff, outOffset, outLen);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        mCBOREncoder.startMap((short) 3);
        //encode key as Namespace string
        mCBOREncoder.encodeTextString(STR_NAME_SPACE, (short)0, (short)STR_NAME_SPACE.length);
        //Hold nameSpace in temp variable
        short nameSpaceLen = mCBORDecoder.readByteString(mCryptoManager.getTempBuffer(), (short) 0);
        //encode nameSpace string
        mCBOREncoder.encodeTextString(mCryptoManager.getTempBuffer(), (short)0, nameSpaceLen);
        //encode key as Name string, lets use it from Namespace string
        mCBOREncoder.encodeTextString(STR_NAME_SPACE, (short)0, (short)4);
        //read name parameter
        short nameLen = mCBORDecoder.readByteString(mCryptoManager.getTempBuffer(), (short) 0);
        mCBOREncoder.encodeTextString(mCryptoManager.getTempBuffer(), (short) 0, nameLen);
        
        mCBORDecoder.skipEntry();
        
        //encode key as AccessControlProfileIds string
        mCBOREncoder.encodeTextString(STR_ACCESS_CONTROL_PROFILE_IDS, (short)0, (short)STR_ACCESS_CONTROL_PROFILE_IDS.length);
        short acpIdLen = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        mCBOREncoder.startArray(acpIdLen);
        for(short i = (short)0; i < acpIdLen; i++) {
        	//Util.arrayCopyNonAtomic(inBuff, mCBORDecoder.getCurrentOffset(), outBuff, mCBOREncoder.getCurrentOffsetAndIncrease(mCBORDecoder.readLength()), mCBORDecoder.readLength());
        	byte intSize = mCBORDecoder.getIntegerSize();
        	if(intSize == 1) {
        		mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
        	} else if(intSize == 2) {
        		mCBOREncoder.encodeUInt16(mCBORDecoder.readInt16());
        	} else {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }
        
        mAdditionalDataDigester.doFinal(outBuff, outOffset, mCBOREncoder.getCurrentOffset(), shaOut, shaOutOff);
        
        return mCBOREncoder.getCurrentOffset();
	}
}
