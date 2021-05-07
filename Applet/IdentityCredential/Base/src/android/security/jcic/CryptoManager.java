package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class CryptoManager {

    public static final byte FLAG_TEST_CREDENTIAL = 0;
    public static final byte FLAG_CREDENIAL_KEYS_INITIALIZED = 1;
    public static final byte FLAG_CREDENIAL_PERSONALIZATION_STATE = 2;
    public static final byte FLAG_CREDENIAL_PERSONALIZING_PROFILES = 3;
    public static final byte FLAG_CREDENIAL_PERSONALIZING_ENTRIES = 4;
    public static final byte FLAG_CREDENIAL_PERSONALIZING_NAMESPACE = 5;
    public static final byte FLAG_CREDENIAL_RETRIEVAL_STARTED = 6;
    public static final byte FLAG_CREDENIAL_RETRIEVAL_ENTRIES = 7;
    public static final byte FLAG_CREDENIAL_RETRIEVAL_CHUNKED = 8;
    public static final byte FLAG_CREDENIAL_RETRIEVAL_NAMESPACE = 9;
    private static final byte STATUS_FLAGS_SIZE = 2;

    /*public static final byte STATUS_PROFILES_TOTAL = 0;
    public static final byte STATUS_PROFILES_PERSONALIZED = 1;
    public static final byte STATUS_ENTRIES_IN_NAMESPACE_TOTAL = 2;
    public static final byte STATUS_ENTRIES_IN_NAMESPACE = 3;
    public static final byte STATUS_ENTRY_AUTHDATA_LENGTH = 4;
    public static final byte STATUS_NAMESPACES_ADDED = 5;
    public static final byte STATUS_NAMESPACES_TOTAL = 6;
    public static final byte STATUS_DOCTYPE_LEN = 7;
    public static final byte STATUS_EPHKEY_LEN = 8;
    private static final byte STATUS_WORDS = 9;*/
    
    public static final byte AES_GCM_KEY_SIZE = 16; 
    public static final byte AES_GCM_TAG_SIZE = 16; 
    public static final byte AES_GCM_IV_SIZE = 12;
    public static final byte EC_KEY_SIZE = 32;
    public static final byte SHA256_DIGEST_SIZE = 32;

    public static final short TEMP_BUFFER_SIZE = 2048;
    public static final short TEMP_BUFFER_DOCTYPE_MAXSIZE = 64;
    public static final short TEMP_BUFFER_DOCTYPE_POS = TEMP_BUFFER_SIZE;
    public static final short TEMP_BUFFER_IV_POS = TEMP_BUFFER_DOCTYPE_POS + TEMP_BUFFER_DOCTYPE_MAXSIZE;
    public static final short TEMP_BUFFER_GCM_TAG_POS = TEMP_BUFFER_IV_POS + AES_GCM_IV_SIZE;
    
    // Actual Crypto implementation
    private final ICryptoProvider mCryptoProvider;
    
    // Hardware bound key, initialized during Applet installation
    private final byte[] mHBK;
    
    // Storage key for a credential
    private final byte[] mCredentialStorageKey;

    // KeyPair for credential key
    private final byte[] mCredentialKeyPair;
    // Temporary buffer in memory for keyLengths
    private final short[] mCredentialKeyPairLengths;

    // KeyPair for credential key generation 
    //private final KeyPair mCredentialECKeyPair;

    // KeyPair for ephemeral key generation
    //private final KeyPair mTempECKeyPair;
    
    //private final Cipher mCipher;
    
    // Signature object for creating and verifying credential signatures 
    //private final Signature mECSignature;

    //private final Signature mHMACSignature;
    
    // Signature object for creating and verifying credential signatures 
    private final MessageDigest mDigest;
    
    // Key for authentication signature computation
    //private final HMACKey mHMACauthKey;
    
    // Helper object to compute the HMAC key from reader ephemeral public key and signing key 
    //private final KeyAgreement mAuthentKeyGen;
    
    // Random data generator 
    private final RandomData mRandomData;
    
    // Reference to the Access control manager instance
    //private final AccessControlManager mAccessControlManager;
    
    // Temporary buffer for all cryptography operations
    private final byte[] mTempBuffer;
    
    // Temporary buffer in memory for status flags
    private final byte[] mStatusFlags;

    // Temporary buffer in memory for status information
    //private final short[] mStatusWords;

    public CryptoManager(APDUManager apduManager, ICryptoProvider cryptoProvider /*AccessControlManager accessControlManager,*/) {
    	mCryptoProvider = cryptoProvider;
    	
        mTempBuffer = JCSystem.makeTransientByteArray((short) (TEMP_BUFFER_SIZE + TEMP_BUFFER_DOCTYPE_MAXSIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE),
                JCSystem.CLEAR_ON_DESELECT);

        mStatusFlags = JCSystem.makeTransientByteArray((short)(STATUS_FLAGS_SIZE), JCSystem.CLEAR_ON_DESELECT);
        //mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
        
        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_TRNG);
        mRandomData.nextBytes(mTempBuffer, (short)0, AES_GCM_KEY_SIZE);
        mHBK = JCSystem.makeTransientByteArray(AES_GCM_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(mTempBuffer, (short) 0, mHBK, (short) 0, AES_GCM_KEY_SIZE);
        
        // Overwrite this new HBK key in the buffer and initialize a test key 
        //Util.arrayFillNonAtomic(mTempBuffer, (short) 0, AES_GCM_KEY_SIZE, (byte) 0);
        //mTestKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        //mTestKey.setKey(mTempBuffer, (short)0);

        // Create the storage key byte array 
        mCredentialStorageKey = JCSystem.makeTransientByteArray(AES_GCM_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPair = JCSystem.makeTransientByteArray((short)(EC_KEY_SIZE * 3 + 1), JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPairLengths = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);
        
        //mCipher = AEADCipher.getInstance(AEADCipher.ALG_AES_GCM, AEADCipher.PAD_PKCS1, false);
        
        // Configure key pair for elliptic curve key generation
        //mCredentialECKeyPair = new KeyPair(
        //        (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
        //        (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false));
        
        //mTempECKeyPair = new KeyPair(
        //        (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
        //        (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false));

        // At the moment we only support SEC-P256r1. Hence, can be configured at install time.
        //Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPrivate());
        //Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPublic());
        //Secp256r1.configureECKeyParameters((ECKey) mTempECKeyPair.getPrivate());
        //Secp256r1.configureECKeyParameters((ECKey) mTempECKeyPair.getPublic());

        // Initialize the object for signing data using EC
        //mECSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        
        mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        //mHMACauthKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
        //        (short) (KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64 * 8), false);
        //mHMACSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

        //mAuthentKeyGen= KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        
        //mAccessControlManager = accessControlManager;
    }

    /**
     * Reset the internal state. Resets the credential private key, the storage key
     * as well as all status flags.
     */
    public void reset() {
        ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_KEYS_INITIALIZED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZATION_STATE, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_PROFILES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_NAMESPACE, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_STARTED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_ENTRIES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_CHUNKED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_NAMESPACE, false);
        
        /*mStatusWords[STATUS_ENTRIES_IN_NAMESPACE] = 0;
        mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL] = 0;
        mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] = 0;
        mStatusWords[STATUS_DOCTYPE_LEN] = 0;
        mStatusWords[STATUS_EPHKEY_LEN] = 0;
        
        ICUtil.shortArrayFillNonAtomic(mStatusWords, (short) 0, STATUS_WORDS, (short) 0);*/

        Util.arrayFillNonAtomic(mCredentialStorageKey, (short)0, KeyBuilder.LENGTH_AES_128, (byte)0);
        //mCredentialECKeyPair.getPrivate().clearKey();
        //Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPrivate());
    }
    
    /**
     * Returns the used AES key size for the storage as well as hardware-bound key
     * in bit.
     */
    public static short getAESKeySize() {
        return (short) (AES_GCM_KEY_SIZE * 8);
    }
    
    void createCredentialStorageKey(boolean testCredential) {
        // Check if it is a test credential
        if(testCredential) { // Test credential
        	Util.arrayFillNonAtomic(mCredentialStorageKey, (short) 0, CryptoManager.AES_GCM_KEY_SIZE, (byte)0x00);
        } else {
	        // Generate the AES-128 storage key 
	        generateRandomData(mCredentialStorageKey, (short) 0, CryptoManager.AES_GCM_KEY_SIZE);
        }
    }
    
    short getCredentialStorageKey(byte[] storageKey, short skStart) {
        if(storageKey != null) {
            Util.arrayCopyNonAtomic(mCredentialStorageKey, (short) 0, storageKey, skStart, AES_GCM_KEY_SIZE);
        }
        return AES_GCM_KEY_SIZE;
    }

    short setCredentialStorageKey(byte[] storageKey, short skStart) {
        if(storageKey != null) {
            Util.arrayCopyNonAtomic(storageKey, skStart, mCredentialStorageKey, (short) 0, AES_GCM_KEY_SIZE);
        }
        return AES_GCM_KEY_SIZE;
    }

    void createEcKeyPair(byte[] keyPairBlob, short keyBlobStart, short[] keyPairLengths) {
        mCryptoProvider.createECKey(keyPairBlob, keyBlobStart, EC_KEY_SIZE, keyPairBlob, (short)(keyBlobStart + EC_KEY_SIZE), (short) (EC_KEY_SIZE * 2 + 1), keyPairLengths);
    }

    void createEcKeyPairAndAttestation(boolean isTestCredential) {
        createEcKeyPair(mCredentialKeyPair, (short)0, mCredentialKeyPairLengths);

        // Only include TAG_IDENTITY_CREDENTIAL_KEY if it's not a test credential
        if (!isTestCredential) {
        	//TODO 
        }
    }
    
    short getCredentialEcKey(byte[] credentialEcKey, short start) {
        if(credentialEcKey != null) {
            Util.arrayCopyNonAtomic(mCredentialKeyPair, (short) 0, credentialEcKey, start, mCredentialKeyPairLengths[0]);
        }
    	return mCredentialKeyPairLengths[0];
    }

    short setCredentialEcKey(byte[] credentialEcKey, short start) {
        if(credentialEcKey != null) {
            Util.arrayCopyNonAtomic(credentialEcKey, start, mCredentialKeyPair, (short) 0, EC_KEY_SIZE);
            mCredentialKeyPairLengths[0] = EC_KEY_SIZE;
        }
        return EC_KEY_SIZE;
    }

    short getCredentialEcPubKey(byte[] credentialEcPubKey, short start) {
        if(credentialEcPubKey != null) {
            Util.arrayCopyNonAtomic(mCredentialKeyPair, mCredentialKeyPairLengths[0], credentialEcPubKey, start, mCredentialKeyPairLengths[1]);
        }
        return mCredentialKeyPairLengths[1];
    }

    short signPreSharedHash(byte[] sha256Hash, short hashOffset, byte[] signBuff, short signBuffOffset) {
    	/* Test data
    	byte[] privKey = new byte[] {(byte) 0x03, (byte) 0x64, (byte) 0x3d, (byte) 0x30, (byte) 0x2e, (byte) 0xad, (byte) 0xbe, (byte) 0x58, (byte) 0x21, (byte) 0xb7, (byte) 0xad, (byte) 0xa2, (byte) 0x21, (byte) 0x45, (byte) 0xfb, (byte) 0x8b, (byte) 0x35, (byte) 0x0a, (byte) 0x6e, (byte) 0x1c, (byte) 0x2a, (byte) 0x42, (byte) 0x50, (byte) 0x11, (byte) 0x46, (byte) 0x2d, (byte) 0xea, (byte) 0x38, (byte) 0x28, (byte) 0x4c, (byte) 0xfe, (byte) 0x7b};
    	sha256Hash = new byte[] {(byte) 0x55, (byte) 0xa1, (byte) 0x22, (byte) 0x0f, (byte) 0x97, (byte) 0x4d, (byte) 0x86, (byte) 0xe6, (byte) 0xff, (byte) 0x0c, (byte) 0x5f, (byte) 0x19, (byte) 0x79, (byte) 0xe7, (byte) 0x7d, (byte) 0xef, (byte) 0x71, (byte) 0xdf, (byte) 0xbd, (byte) 0x92, (byte) 0xa7, (byte) 0x21, (byte) 0xe3, (byte) 0x0d, (byte) 0x8f, (byte) 0x34, (byte) 0x8e, (byte) 0xfd, (byte) 0xa6, (byte) 0xf4, (byte) 0x0f, (byte) 0xe2};
    	hashOffset = (short) 0;
    	Util.arrayCopyNonAtomic(privKey, (short) 0, mCredentialKeyPair, (short) 0, EC_KEY_SIZE);
    	/* Test data finish */
    	
    	ICryptoOperation signer = mCryptoProvider.initECSignWithNoDigestOperation(
    																mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0], //Private key
    																mCredentialKeyPair, EC_KEY_SIZE, mCredentialKeyPairLengths[1]); //Public key
    	
    	return signer.sign(sha256Hash, hashOffset, SHA256_DIGEST_SIZE, signBuff, signBuffOffset);
    }
    
    void setStatusFlag(byte flag, boolean isSet) {
    	ICUtil.setBit(mStatusFlags, flag, isSet);
    }
    

    boolean getStatusFlag(byte flag) {
    	return ICUtil.getBit(mStatusFlags, flag);
    }
    
    void generateRandomData(byte[] tempBuffer, short offset, short length) {
        mRandomData.nextBytes(tempBuffer, offset, length);
    }
    
    byte[] getTempBuffer() {
    	return mTempBuffer;
    }
    

    public void assertStatusFlagSet(byte statusFlag) {
        if (!ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    public void assertCredentialInitialized() {
        assertStatusFlagSet(FLAG_CREDENIAL_KEYS_INITIALIZED);
    }

    public void assertInPersonalizationState() {
        assertStatusFlagSet(FLAG_CREDENIAL_PERSONALIZATION_STATE);
    }

    public void assertStatusFlagNotSet(byte statusFlag) {
        if (ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
//byte[] nonce = new byte[] {(byte)0xBD, (byte)0xB1, (byte)0xEE, (byte)0xE0, (byte)0x31, (byte)0x3D, (byte)0x90, (byte)0xA0, (byte)0xDE, (byte)0x08, (byte)0x35, (byte)0x87};
//byte[] storeageKey = new byte[] {(byte)0xAD, (byte)0xE1, (byte)0x65, (byte)0xBC, (byte)0xA8, (byte)0xD5, (byte)0x45, (byte)0x3D, (byte)0x3B, (byte)0xAD, (byte)0x73, (byte)0x9C, (byte)0x72, (byte)0x53, (byte)0x8C, (byte)0x58};
    public short aesGCMEncrypt(byte[] data, short dataOffset, short dataLen,
    		byte[] outData, short outDataOffset,
    		byte[] authData, short authDataOffset, short authDataLen,
    		byte[] outNonceAndTag, short outNonceAndTagOff) {

        // Generate the IV
        mRandomData.nextBytes(outNonceAndTag, outNonceAndTagOff, AES_GCM_IV_SIZE);
    	return mCryptoProvider.aesGCMEncrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
    			data, dataOffset, dataLen,
    			outData, outDataOffset,
    			outNonceAndTag, (short)outNonceAndTagOff, AES_GCM_IV_SIZE,
    			authData, authDataOffset, authDataLen,
    			outNonceAndTag, (short)(outNonceAndTagOff + AES_GCM_IV_SIZE), AES_GCM_TAG_SIZE);
    	
    	/*Util.arrayCopyNonAtomic(nonce, (short) 0, outNonceAndTag, (short) outNonceAndTagOff, AES_GCM_IV_SIZE);
    	return mCryptoProvider.aesGCMEncrypt(storeageKey, (short)0, (short)(storeageKey.length),
    			data, dataOffset, dataLen,
    			outData, outDataOffset,
    			outNonceAndTag, (short)outNonceAndTagOff, AES_GCM_IV_SIZE,
    			authData, authDataOffset, authDataLen,
    			outNonceAndTag, (short)(outNonceAndTagOff + AES_GCM_IV_SIZE), AES_GCM_TAG_SIZE);
		*/
    }
    
    short entryptCredentialData(boolean isTestCredential,
    		byte[] data, short dataOffset, short dataLen,
    		byte[] outData, short outDataOffset,
    		byte[] authData, short authDataOffset, short authDataLen,
    		byte[] outNonceAndTag, short outNonceAndTagOff) {

        // Generate the IV
        mRandomData.nextBytes(outNonceAndTag, outNonceAndTagOff, AES_GCM_IV_SIZE);
        if(isTestCredential) {
        	//In case of testCredential HBK should be initialized with 0's
        	//If testCredential is true mCredentialStorageKey is already initialized with 0's so no need to create separate HBK for testCredential.
        	return mCryptoProvider.aesGCMEncrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
	    			data, dataOffset, dataLen,
	    			outData, outDataOffset,
	    			outNonceAndTag, (short)outNonceAndTagOff, AES_GCM_IV_SIZE,
	    			authData, authDataOffset, authDataLen,
	    			outNonceAndTag, (short)(outNonceAndTagOff + AES_GCM_IV_SIZE), AES_GCM_TAG_SIZE);
        } else {
	    	return mCryptoProvider.aesGCMEncrypt(mHBK, (short)0, (short)mHBK.length,
	    			data, dataOffset, dataLen,
	    			outData, outDataOffset,
	    			outNonceAndTag, (short)outNonceAndTagOff, AES_GCM_IV_SIZE,
	    			authData, authDataOffset, authDataLen,
	    			outNonceAndTag, (short)(outNonceAndTagOff + AES_GCM_IV_SIZE), AES_GCM_TAG_SIZE);
        }
    }

    void decryptCredentialData(boolean isTestCredential, byte[] encryptedCredentialKeyBlob, short keyBlobOff, short keyBlobSize,
                                            byte[] outData, short outDataOffset,
                                            byte[] nonce, short nonceOffset, short nonceLen,
                                            byte[] authData, short authDataOffset, short authDataLen,
                                            byte[] authTag, short authTagOffset, short authTagLen) {

        if(isTestCredential) {
            mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        } else {
            mCryptoProvider.aesGCMDecrypt(mHBK, (short)0, (short)mHBK.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        }
    }
}
