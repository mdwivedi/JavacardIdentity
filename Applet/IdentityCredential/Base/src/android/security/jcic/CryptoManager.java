package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;

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

    public static final short TEMP_BUFFER_SIZE = 128;
    public static final short TEMP_BUFFER_DOCTYPE_MAXSIZE = 64;
    public static final short TEMP_BUFFER_DOCTYPE_POS = TEMP_BUFFER_SIZE;
    public static final short TEMP_BUFFER_IV_POS = TEMP_BUFFER_DOCTYPE_POS + TEMP_BUFFER_DOCTYPE_MAXSIZE;
    
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
    public static final byte AES_GCM_IV_SIZE = 12;
    public static final byte EC_KEY_SIZE = 32;
    public static final byte DIGEST_SIZE = 32;

    // Actual Crypto implementation
    private final CryptoProvider mCryptoProvider;
    
    // Hardware bound key, initialized during Applet installation
    private final AESKey mHBK;
    
    // Test key, initialized with only zeros during Applet installation
    private final AESKey mTestKey;

    // Storage key for a credential
    private final AESKey mCredentialStorageKey;

    // KeyPair for credential key generation 
    //private final KeyPair mCredentialECKeyPair;

    // KeyPair for ephemeral key generation
    //private final KeyPair mTempECKeyPair;
    
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

    public CryptoManager(APDUManager apduManager, CryptoProvider cryptoProvider /*AccessControlManager accessControlManager,*/) {
    	mCryptoProvider = cryptoProvider;
    	
        mTempBuffer = JCSystem.makeTransientByteArray((short) (TEMP_BUFFER_SIZE + TEMP_BUFFER_DOCTYPE_MAXSIZE + AES_GCM_IV_SIZE),
                JCSystem.CLEAR_ON_DESELECT);

        mStatusFlags = JCSystem.makeTransientByteArray((short)(STATUS_FLAGS_SIZE), JCSystem.CLEAR_ON_DESELECT);
        //mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
        
        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_TRNG);
        mRandomData.nextBytes(mTempBuffer, (short)0, AES_GCM_KEY_SIZE);
        mHBK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mHBK.setKey(mTempBuffer, (short)0);
        
        // Overwrite this new HBK key in the buffer and initialize a test key 
        Util.arrayFillNonAtomic(mTempBuffer, (short) 0, AES_GCM_KEY_SIZE, (byte) 0);
        mTestKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mTestKey.setKey(mTempBuffer, (short)0);

        // Create the storage key instance 
        mCredentialStorageKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        
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

        mCredentialStorageKey.clearKey();
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
    
    /**
     * Return Hardware Backed Key associated with applet.
     */
    AESKey getHBK() {
    	return mHBK;
    }

    /**
     * Return test key filled with 0s.
     */
    AESKey getTestKey() {
    	return mTestKey;
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
    
    AESKey getCredentialStorageKey() {
    	return mCredentialStorageKey;
    }

    //KeyPair getCredentialECKeyPair() {
    //	return mCredentialECKeyPair;
    //}
    
    byte[] getTempBuffer() {
    	return mTempBuffer;
    }
    

    private void assertStatusFlagSet(byte statusFlag) {
        if (!ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    public void assertCredentialInitialized() {
        assertStatusFlagSet(FLAG_CREDENIAL_KEYS_INITIALIZED);
    }

}
