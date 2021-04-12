package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.MessageDigest;
import javacardx.framework.util.intx.JCint;

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
    
    private static final byte[] STR_SIGNATURE1 = new byte[] {(byte)0x53, (byte)0x69, (byte)0x67, (byte)0x6E, (byte)0x61,
															(byte)0x74, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x31};
    private static final byte[] STR_PROOF_OF_PROVISIONING = new byte[] {(byte)0x50, (byte)0x72, (byte)0x6f, (byte)0x6f,
    														(byte)0x66, (byte)0x4f, (byte)0x66, (byte)0x50, (byte)0x72,
    														(byte)0x6f, (byte)0x76, (byte)0x69, (byte)0x73, (byte)0x69,
    														(byte)0x6f, (byte)0x6e, (byte)0x69, (byte)0x6e, (byte)0x67};
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
	            break;
	        case ISO7816.INS_ICS_BEGIN_ADD_ENTRY:
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
        } else if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Generate the AES-128 storage key 
        mCryptoManager.generateRandomData(tempBuffer, (short) 0, CryptoManager.AES_GCM_KEY_SIZE);
        mCryptoManager.getCredentialStorageKey().setKey(tempBuffer, (short) 0);

        // Credential keys are loaded
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_KEYS_INITIALIZED, true);
	}
	
	private void processStartPersonalization() {
        mCryptoManager.assertCredentialInitialized();

        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();

        short le = mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();

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
    		//outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
    		mCBOREncoder.startByteString(mCBORDecoder.readInt8());
    	} else if (intSize == 2) {
    		outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_TWO_BYTES;
    		Util.arrayCopy(receiveBuffer, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuffer, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
    	} else if(intSize == 4) {
    		outBuffer[mCBOREncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_FOUR_BYTES;
    		Util.arrayCopy(receiveBuffer, (short)(mCBORDecoder.getCurrentOffset() + 1), outBuffer, mCBOREncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
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
        mDigest.doFinal(mCryptoManager.getTempBuffer(), (short)0, (short)0, outBuffer, (short)0);
        
        mAPDUManager.setOutgoingLength((short)MessageDigest.LENGTH_SHA_256);
        // Set the Applet in the PERSONALIZATION state
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_PERSONALIZATION_STATE, true);
		
	}
}
