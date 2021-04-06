package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;

/**
 * A class to handle all provisioning related operations
 * with the help of CryptoManager and CBOR encoder and decoder.
 *
 */
public class JCICProvisioning {
	// Reference to internal Crypto Manager instance
	private CryptoManager mCryptoManager;
	
    // Reference to the internal APDU manager instance
    private final APDUManager mAPDUManager;
    
    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;

    

	public JCICProvisioning(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
	}

	public void reset() {
		mCryptoManager.reset();
		mAPDUManager.reset();
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

        // Create a new credential key
        mCryptoManager.getCredentialECKeyPair().genKeyPair();

        // Credential keys are loaded
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_KEYS_INITIALIZED, true);

        // Set the Applet in the PERSONALIZATION state
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_CREDENIAL_PERSONALIZATION_STATE, true);
	}
}
