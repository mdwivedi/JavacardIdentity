package android.security.jcic;

import com.android.javacard.keymaster.*;
import javacard.framework.Util;
import javacard.security.*;
import javacard.security.KeyPair;
import javacard.security.Signature;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class CryptoProviderImpl implements ICryptoProvider{
	private final KMSEProvider kmSEProvider;
	private final Signature mHMACSignature;
	private final KeyPair mECKeyPair1;
	private final KeyAgreement mECDHAgreement;
	private java.security.Signature sunSigner;
	
	CryptoProviderImpl() {
		kmSEProvider = new KMJCardSimulator();
		mHMACSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
		mECKeyPair1 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		mECDHAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		try {
			sunSigner = java.security.Signature.getInstance("NONEwithECDSA", "SunEC");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {

		}
	}

	@Override
	public void createECKey(byte[] privKeyBuf, short privKeyStart, short privKeyMaxLength,
			byte[] pubModBuf, short pubModStart, short pubModMaxLength, short[] lengths) {
		kmSEProvider.createAsymmetricKey(KMType.EC, privKeyBuf, privKeyStart, privKeyMaxLength,
				pubModBuf, pubModStart, pubModMaxLength, lengths);
	}

	@Override
	public short ecSignWithNoDigest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
									byte[] data, short dataStart, short dataLength,
									byte[] outSign, short outSignStart) {

    	KMOperation signer = kmSEProvider.initAsymmetricOperation(KMType.SIGN, KMType.EC,  KMType.PADDING_NONE , KMType.DIGEST_NONE,
    			privKeyBuf, privKeyStart, privKeyLength, //Private key
				privKeyBuf, (short)0, (short)0); //Public key
    	
		return signer.sign(data, dataStart, dataLength, outSign, outSignStart);
	}

	@Override
	public short aesGCMEncrypt(byte[] aesKey, short aesKeyStart, short aesKeyLen, byte[] data, short dataStart,
			short dataLen, byte[] encData, short encDataStart, byte[] nonce, short nonceStart, short nonceLen,
			byte[] authData, short authDataStart, short authDataLen, byte[] authTag, short authTagStart,
			short authTagLen) {
		return kmSEProvider.aesGCMEncrypt(aesKey, aesKeyStart, aesKeyLen, data, dataStart,
				dataLen, encData, encDataStart, nonce, nonceStart, nonceLen,
				authData, authDataStart, authDataLen, authTag, authTagStart,
				authTagLen);
	}

	@Override
	public boolean aesGCMDecrypt(byte[] aesKey, short aesKeyStart, short aesKeyLen, byte[] data, short dataStart,
							   short dataLen, byte[] encData, short encDataStart, byte[] nonce, short nonceStart, short nonceLen,
							   byte[] authData, short authDataStart, short authDataLen, byte[] authTag, short authTagStart,
							   short authTagLen) {
		return kmSEProvider.aesGCMDecrypt(aesKey, aesKeyStart, aesKeyLen,
				data, dataStart, dataLen,
				encData, encDataStart,
				nonce, nonceStart, nonceLen,
				authData, authDataStart, authDataLen,
				authTag, authTagStart, authTagLen);
	}

	@Override
	public short ecSignWithSHA256Digest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
										byte[] data, short dataStart, short dataLength,
										byte[] outSign, short outSignStart) {

		KMOperation signer = kmSEProvider.initAsymmetricOperation(KMType.SIGN, KMType.EC,  KMType.PADDING_NONE , KMType.SHA2_256,
				privKeyBuf, privKeyStart, privKeyLength, //Private key
				privKeyBuf, (short)0, (short)0); //Public key

		return signer.sign(data, dataStart, dataLength, outSign, outSignStart);
	}

	@Override
	public boolean ecVerifyWithNoDigest(byte[] pubKeyBuf, short pubKeyStart, short pubKeyLength,
                                        byte[] data, short dataStart, short dataLength,
                                        byte[] signBuf, short signStart, short signLength) {
		boolean result;
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("EC");
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
			//Supported curve secp256r1
			parameters.init(new ECGenParameterSpec("secp256r1"));
			ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
			//Check if  the first byte is 04 and remove it.
			if (pubKeyBuf[pubKeyStart] == 0x04) {
				//uncompressed format.
				pubKeyStart++;
				pubKeyLength--;
			}
			short i = 0;
			byte[] pubx = new byte[pubKeyLength / 2];
			for (; i < pubKeyLength / 2; i++) {
				pubx[i] = pubKeyBuf[pubKeyStart + i];
			}
			byte[] puby = new byte[pubKeyLength / 2];
			for (i = 0; i < pubKeyLength / 2; i++) {
				puby[i] = pubKeyBuf[pubKeyStart + pubKeyLength / 2 + i];
			}
			BigInteger bIX = new BigInteger(pubx);
			BigInteger bIY = new BigInteger(puby);
			ECPoint point = new ECPoint(bIX, bIY);
			ECPublicKeySpec pubkeyspec = new ECPublicKeySpec(point, ecParameters);
			java.security.interfaces.ECPublicKey pubkey = (java.security.interfaces.ECPublicKey) kf.generatePublic(pubkeyspec);
			sunSigner.initVerify(pubkey);
			sunSigner.update(data, dataStart, dataLength);
			result = sunSigner.verify(signBuf, signStart, signLength);
		} catch(Exception e) {
			result = false;
		}
		return result;
	}

	@Override
	public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
								  byte[] pubKey, short pubKeyOffset, short pubKeyLen,
								  byte[] outSecret, short outSecretOffset) {
		ECPrivateKey privateKey = (ECPrivateKey) mECKeyPair1.getPrivate();
		privateKey.setS(privKey, privKeyOffset, privKeyLen);
		mECDHAgreement.init(privateKey);
		short result = (short)0;
		try {
			result = mECDHAgreement.generateSecret(pubKey, pubKeyOffset, pubKeyLen, outSecret, outSecretOffset);
		}catch (Exception e){
			e.printStackTrace();
		}
		return result;
	}

	@Override
	public short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
					  byte[] salt, short saltOffset, short saltLen,
					  byte[] info, short infoOffset, short infoLen,
					  byte[] outDerivedKey, short outDerivedKeyOffset, short expectedDerivedKeyLen) {
		// HMAC_extract
		byte[] prk = new byte[32];
		hkdfExtract(sharedSecret, sharedSecretOffset, sharedSecretLen, salt, saltOffset, saltLen, prk, (short) 0);
		//HMAC_expand
		return hkdfExpand(prk, (short) 0, (short) 32, info, infoOffset, infoLen, outDerivedKey, outDerivedKeyOffset, expectedDerivedKeyLen);
	}

	private short hkdfExtract(byte[] ikm, short ikmOff, short ikmLen, byte[] salt, short saltOff, short saltLen,
							  byte[] out, short off) {
		// https://tools.ietf.org/html/rfc5869#section-2.2
		HMACKey hmacKey = createHMACKey(salt, saltOff, saltLen);
		mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
		return mHMACSignature.sign(ikm, ikmOff, ikmLen, out, off);
	}

	private short hkdfExpand(byte[] prk, short prkOff, short prkLen, byte[] info, short infoOff, short infoLen,
							 byte[] out, short outOff, short outLen) {
		// https://tools.ietf.org/html/rfc5869#section-2.3
		short digestLen = (short) 32; // SHA256 digest length.
		// Calculate no of iterations N.
		short n = (short) ((outLen + digestLen - 1) / digestLen);
		if (n > 255) {
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		HMACKey hmacKey = createHMACKey(prk, prkOff, prkLen);
		byte[] previousOutput = new byte[32]; // Length of output 32.
		byte[] cnt = {(byte) 0};
		short bytesCopied = 0;
		short len = 0;
		for (short i = 0; i < n; i++) {
			cnt[0]++;
			mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
			if (i != 0)
				mHMACSignature.update(previousOutput, (short) 0, (short) 32);
			mHMACSignature.update(info, infoOff, infoLen);
			len = mHMACSignature.sign(cnt, (short) 0, (short) 1, previousOutput, (short) 0);
			if ((short) (bytesCopied + len) > outLen) {
				len = (short) (outLen - bytesCopied);
			}
			Util.arrayCopyNonAtomic(previousOutput, (short) 0, out, (short) (outOff + bytesCopied), len);
			bytesCopied += len;
		}
		return outLen;
	}
	public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
		HMACKey key = null;
		key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
				KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
		key.setKey(secretBuffer, secretOff, secretLength);
		return key;
	}
}
