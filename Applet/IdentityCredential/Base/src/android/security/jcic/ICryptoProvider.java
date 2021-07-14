package android.security.jcic;

public interface ICryptoProvider {

	  /**
	   * Create a asymmetric key pair. If the algorithms are not supported then it should throw a
	   * CryptoException. For RSA the public key exponent must always be 0x010001. The key size of RSA
	   * key pair must be 2048 bits and key size of EC key pair must be for p256 curve.
	   *
	   * @param alg will be KMType.RSA or KMType.EC.
	   * @param privKeyBuf is the buffer to return the private key exponent in case of RSA or private
	   * key in case of EC.
	   * @param privKeyStart is the start offset.
	   * @param privKeyMaxLength is the maximum length of this private key buffer.
	   * @param pubModBuf is the buffer to return the modulus in case of RSA or public key in case of
	   * EC.
	   * @param pubModStart is the start of offset.
	   * @param pubModMaxLength is the maximum length of this public key buffer.
	   * @param lengths is the actual length of the key pair - lengths[0] should be private key and
	   * lengths[1] should be public key.
	   */
	  void createECKey(
	      byte[] privKeyBuf,
	      short privKeyStart,
	      short privKeyMaxLength,
	      byte[] pubModBuf,
	      short pubModStart,
	      short pubModMaxLength,
	      short[] lengths);


	short ecSignWithNoDigest(
	      byte[] privKeyBuf,
	      short privKeyStart,
	      short privKeyLength,
	      byte[] data,
		  short dataStart,
		  short dataLength,
	      byte[] outSign,
		  short outSignStart);

	short ecSignWithSHA256Digest(
			byte[] privKeyBuf,
			short privKeyStart,
			short privKeyLength,
			byte[] data,
			short dataStart,
			short dataLength,
			byte[] outSign,
			short outSignStart);

	boolean ecVerifyWithNoDigest(
			byte[] pubModBuf, short pubModStart, short pubModLength,
			byte[] data, short dataStart, short dataLength,
			byte[] signBuf, short signStart, short signLength);

	  /**
	   * This is a oneshot operation that performs encryption operation using AES GCM algorithm. It
	   * throws CryptoException if algorithm is not supported or if tag length is not equal to 16 or
	   * nonce length is not equal to 12.
	   *
	   * @param aesKey is the buffer that contains 128 bit or 256 bit aes key used to encrypt.
	   * @param aesKeyStart is the start in aes key buffer.
	   * @param aesKeyLen is the length of aes key buffer in bytes (16 or 32 bytes).
	   * @param data is the buffer that contains data to encrypt.
	   * @param dataStart is the start of the data buffer.
	   * @param dataLen is the length of the data buffer.
	   * @param encData is the buffer of the output encrypted data.
	   * @param encDataStart is the start of the encrypted data buffer.
	   * @param nonce is the buffer of nonce.
	   * @param nonceStart is the start of the nonce buffer.
	   * @param nonceLen is the length of the nonce buffer.
	   * @param authData is the authentication data buffer.
	   * @param authDataStart is the start of the authentication buffer.
	   * @param authDataLen is the length of the authentication buffer.
	   * @param authTag is the buffer to output authentication tag.
	   * @param authTagStart is the start of the buffer.
	   * @param authTagLen is the length of the buffer.
	   * @return length of the encrypted data.
	   */
	  short aesGCMEncrypt(
	      byte[] aesKey,
	      short aesKeyStart,
	      short aesKeyLen,
	      byte[] data,
	      short dataStart,
	      short dataLen,
	      byte[] encData,
	      short encDataStart,
	      byte[] nonce,
	      short nonceStart,
	      short nonceLen,
	      byte[] authData,
	      short authDataStart,
	      short authDataLen,
	      byte[] authTag,
	      short authTagStart,
	      short authTagLen);

	/**
	 * This is a oneshot operation that performs decryption operation using AES GCM algorithm. It
	 * throws CryptoException if algorithm is not supported.
	 *
	 * @param aesKey is the buffer that contains 128 bit or 256 bit aes key used to encrypt.
	 * @param aesKeyStart is the start in aes key buffer.
	 * @param aesKeyLen is the length of aes key buffer in bytes (16 or 32 bytes).
	 * @param encData is the buffer of the input encrypted data.
	 * @param encDataStart is the start of the encrypted data buffer.
	 * @param encDataLen is the length of the data buffer.
	 * @param data is the buffer that contains output decrypted data.
	 * @param dataStart is the start of the data buffer.
	 * @param nonce is the buffer of nonce.
	 * @param nonceStart is the start of the nonce buffer.
	 * @param nonceLen is the length of the nonce buffer.
	 * @param authData is the authentication data buffer.
	 * @param authDataStart is the start of the authentication buffer.
	 * @param authDataLen is the length of the authentication buffer.
	 * @param authTag is the buffer to output authentication tag.
	 * @param authTagStart is the start of the buffer.
	 * @param authTagLen is the length of the buffer.
	 * @return true if the authentication is valid.
	 */
	boolean aesGCMDecrypt(
			byte[] aesKey,
			short aesKeyStart,
			short aesKeyLen,
			byte[] encData,
			short encDataStart,
			short encDataLen,
			byte[] data,
			short dataStart,
			byte[] nonce,
			short nonceStart,
			short nonceLen,
			byte[] authData,
			short authDataStart,
			short authDataLen,
			byte[] authTag,
			short authTagStart,
			short authTagLen);

	short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
						   byte[] pubKey, short pubKeyOffset, short pubKeyLen,
						   byte[] outSecret, short outSecretOffset);

	short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
			   byte[] salt, short saltOffset, short saltLen,
			   byte[] info, short infoOffset, short infoLen,
			   byte[] outDerivedKey, short outDerivedKeyOffset, short expectedDerivedKeyLen);

	boolean hmacVerify(byte[] key, short keyOffset, short keyLen,
					   byte[] data, short dataOffset, short dataLen,
					   byte[] mac, short macOffset, short macLen);

	boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen,
							   byte[] pubKey, short pubKeyOffset, short pubKeyLen);
}
