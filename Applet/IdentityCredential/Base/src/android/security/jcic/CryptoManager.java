package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class CryptoManager {

    public static final byte FLAG_TEST_CREDENTIAL = 0;
    public static final byte FLAG_CREDENTIAL_KEYS_INITIALIZED = 1;
    public static final byte FLAG_CREDENTIAL_PERSONALIZATION_STATE = 2;
    public static final byte FLAG_CREDENTIAL_PERSONALIZING_PROFILES = 3;
    public static final byte FLAG_CREDENTIAL_PERSONALIZING_ENTRIES = 4;
    public static final byte FLAG_CREDENTIAL_PERSONALIZING_NAMESPACE = 5;
    public static final byte FLAG_CREDENTIAL_RETRIEVAL_STARTED = 6;
    public static final byte FLAG_CREDENTIAL_RETRIEVAL_ENTRIES = 7;
    public static final byte FLAG_CREDENTIAL_RETRIEVAL_CHUNKED = 8;
    public static final byte FLAG_CREDENTIAL_RETRIEVAL_NAMESPACE = 9;
    public static final byte FLAG_UPDATE_CREDENTIAL = 0x0A;
    public static final byte FLAG_HMAC_INITIALIZED = 0x0B;
    private static final byte STATUS_FLAGS_SIZE = 2;

    public static final byte AES_GCM_KEY_SIZE = 16; 
    public static final byte AES_GCM_TAG_SIZE = 16; 
    public static final byte AES_GCM_IV_SIZE = 12;
    public static final byte EC_KEY_SIZE = 32;
    public static final byte SHA256_DIGEST_SIZE = 32;

    public static final short TEMP_BUFFER_SIZE = 2048;
    public static final short TEMP_BUFFER_IV_POS = TEMP_BUFFER_SIZE;
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

    // Signature object for creating and verifying credential signatures 
    final MessageDigest mDigest;
    // Digester object for calculating proof of provisioning data digest
    final MessageDigest mSecondaryDigest;
    // Digester object for calculating addition data digest
    final MessageDigest mAdditionalDataDigester;

    // Random data generator 
    private final RandomData mRandomData;

    // Temporary buffer for all cryptography operations
    private final byte[] mTempBuffer;
    
    // Temporary buffer in memory for status flags
    private final byte[] mStatusFlags;

    //TODO pre-shared key is hardcoded for now but we need to get it through either provisioning or from keymaster
    private byte[] mPreSharedKey = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    public CryptoManager(ICryptoProvider cryptoProvider /*AccessControlManager accessControlManager,*/) {
    	mCryptoProvider = cryptoProvider;
    	
        mTempBuffer = JCSystem.makeTransientByteArray((short) (TEMP_BUFFER_SIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE),
                JCSystem.CLEAR_ON_DESELECT);

        mStatusFlags = JCSystem.makeTransientByteArray((short)(STATUS_FLAGS_SIZE), JCSystem.CLEAR_ON_DESELECT);

        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_TRNG);
        mRandomData.nextBytes(mTempBuffer, (short)0, AES_GCM_KEY_SIZE);
        mHBK = new byte[AES_GCM_KEY_SIZE];
        Util.arrayCopyNonAtomic(mTempBuffer, (short) 0, mHBK, (short) 0, AES_GCM_KEY_SIZE);
        Util.arrayFillNonAtomic(mTempBuffer, (byte)0, AES_GCM_KEY_SIZE, (byte)0);

        // Create the storage key byte array 
        mCredentialStorageKey = JCSystem.makeTransientByteArray(AES_GCM_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPair = JCSystem.makeTransientByteArray((short)(EC_KEY_SIZE * 3 + 1), JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPairLengths = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);

        mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mSecondaryDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mAdditionalDataDigester = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    }

    /**
     * Reset the internal state. Resets the credential private key, the storage key
     * as well as all status flags.
     */
    public void reset() {
        ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_KEYS_INITIALIZED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_PERSONALIZATION_STATE, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_PERSONALIZING_PROFILES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_PERSONALIZING_NAMESPACE, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_RETRIEVAL_STARTED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_RETRIEVAL_ENTRIES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_RETRIEVAL_CHUNKED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENTIAL_RETRIEVAL_NAMESPACE, false);

        Util.arrayFillNonAtomic(mCredentialStorageKey, (short)0, KeyBuilder.LENGTH_AES_128, (byte)0);
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

    short ecSignWithNoDigest(byte[] sha256Hash, short hashOffset, byte[] signBuff, short signBuffOffset) {
    	return mCryptoProvider.ecSignWithNoDigest(mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0],//Private key
                sha256Hash, hashOffset, SHA256_DIGEST_SIZE, signBuff, signBuffOffset);
    }

    short ecSignWithSHA256Digest(byte[] data, short dataOffset, short dataLen, byte[] signBuff, short signBuffOffset) {
        return mCryptoProvider.ecSignWithSHA256Digest(
                mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0],//Private key
                data, dataOffset, dataLen, signBuff, signBuffOffset);
    }

    boolean ecVerifyWithNoDigest(byte[] pubKey, short pubKeyOffset, short pubKeyLen,
                                 byte[] data, short dataOffset, short dataLen,
                                 byte[] signBuff, short signBuffOffset, short signLength) {
        return mCryptoProvider.ecVerifyWithNoDigest(pubKey, pubKeyOffset, pubKeyLen, data, dataOffset, dataLen, signBuff, signBuffOffset, signLength);
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
        assertStatusFlagSet(FLAG_CREDENTIAL_KEYS_INITIALIZED);
    }

    public void assertInPersonalizationState() {
        assertStatusFlagSet(FLAG_CREDENTIAL_PERSONALIZATION_STATE);
    }

    public void assertStatusFlagNotSet(byte statusFlag) {
        if (ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
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
    }

    public boolean aesGCMDecrypt(byte[] encData, short encDataOffset, short encDataLen,
                               byte[] outData, short outDataOffset,
                               byte[] authData, short authDataOffset, short authDataLen,
                               byte[] nonceAndTag, short nonceAndTagOff) {

        return mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                encData, encDataOffset, encDataLen,
                outData, outDataOffset,
                nonceAndTag, nonceAndTagOff, AES_GCM_IV_SIZE,
                authData, authDataOffset, authDataLen,
                nonceAndTag, (short)(nonceAndTagOff + AES_GCM_IV_SIZE), AES_GCM_TAG_SIZE);
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

    boolean decryptCredentialData(boolean isTestCredential, byte[] encryptedCredentialKeyBlob, short keyBlobOff, short keyBlobSize,
                                            byte[] outData, short outDataOffset,
                                            byte[] nonce, short nonceOffset, short nonceLen,
                                            byte[] authData, short authDataOffset, short authDataLen,
                                            byte[] authTag, short authTagOffset, short authTagLen) {

        if(isTestCredential) {
            //In case of testCredential HBK should be initialized with 0's
            //If testCredential is true mCredentialStorageKey is already initialized with 0's so no need to create separate HBK for testCredential.
            return mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        } else {
            return mCryptoProvider.aesGCMDecrypt(mHBK, (short)0, (short)mHBK.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        }
    }

    public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
                                  byte[] pubKey, short pubKeyOffset, short pubKeyLen,
                                  byte[] outSecret, short outSecretOffset) {
        return mCryptoProvider.createECDHSecret(privKey, privKeyOffset, privKeyLen,
                pubKey, pubKeyOffset, pubKeyLen,
                outSecret, outSecretOffset);
    }

    public short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
                      byte[] salt, short saltOffset, short saltLen,
                      byte[] info, short infoOffset, short infoLen,
                      byte[] outDerivedKey, short outDerivedKeyOffset, short expectedKeySize) {
        return mCryptoProvider.hkdf(sharedSecret, sharedSecretOffset, sharedSecretLen,
                                    salt, saltOffset, saltLen,
                                    info, infoOffset, infoLen,
                                    outDerivedKey, outDerivedKeyOffset, expectedKeySize);
    }

    public byte[] getPresharedHmacKey() {
        return mPreSharedKey;
    }

    public boolean hmacVerify(byte[] key, short keyOffset, short keyLen,
                              byte[] data, short dataOffset, short dataLen,
                              byte[] mac, short macOffset, short macLen) {
        return mCryptoProvider.hmacVerify(key, keyOffset, keyLen,
                                    data, dataOffset, dataLen,
                                    mac, macOffset, macLen);
    }

    public boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen, byte[] pubKey, short pubKeyOffset, short pubKeyLen) {
        return mCryptoProvider.verifyCertByPubKey(cert, certOffset, certLen, pubKey, pubKeyOffset, pubKeyLen);
    }
}
