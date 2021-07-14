package android.security.jcic;

import com.android.javacard.keymaster.*;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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
	private Signature signerNoDigest;
	private Signature signerWithSha256;
	private KeyPair ecKeyPair;
	
	CryptoProviderImpl() {
		kmSEProvider = new KMJCardSimulator();
		mHMACSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
		mECKeyPair1 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		mECDHAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		signerNoDigest = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		signerWithSha256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
	}

	@Override
	public void createECKey(byte[] privKeyBuf, short privKeyStart, short privKeyMaxLength,
			byte[] pubModBuf, short pubModStart, short pubModMaxLength, short[] lengths) {
		ecKeyPair.genKeyPair();

		ECPrivateKey privateKey = (ECPrivateKey) ecKeyPair.getPrivate();
		Secp256r1.configureECKeyParameters(privateKey);
		lengths[0] = privateKey.getS(privKeyBuf, privKeyStart);
		ECPublicKey publicKey = (ECPublicKey) ecKeyPair.getPublic();
		Secp256r1.configureECKeyParameters(publicKey);
		lengths[1] = publicKey.getW(pubModBuf, pubModStart);
	}

	@Override
	public short ecSignWithNoDigest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
									byte[] data, short dataStart, short dataLength,
									byte[] outSign, short outSignStart) {

		ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
		Secp256r1.configureECKeyParameters(key);
		key.setS(privKeyBuf, privKeyStart, privKeyLength);
		signerNoDigest.init(key, Signature.MODE_SIGN);
    	return signerNoDigest.signPreComputedHash(data, dataStart, dataLength, outSign, outSignStart);
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
		ECPublicKey pubKey = (ECPublicKey)ecKeyPair.getPublic();
		Secp256r1.configureECKeyParameters(pubKey);
		pubKey.setW(pubKeyBuf, pubKeyStart, pubKeyLength);
		signerNoDigest.init(pubKey, Signature.MODE_VERIFY);
		return signerNoDigest.verifyPreComputedHash(data, dataStart, dataLength, signBuf, signStart, signLength);
	}

	@Override
	public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
								  byte[] pubKey, short pubKeyOffset, short pubKeyLen,
								  byte[] outSecret, short outSecretOffset) {
		ECPrivateKey privateKey = (ECPrivateKey) mECKeyPair1.getPrivate();
		Secp256r1.configureECKeyParameters(privateKey);
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

	@Override
	public boolean hmacVerify(byte[] key, short keyOffset, short keyLen, byte[] data, short dataOffset, short dataLen, byte[] mac, short macOffset, short macLen) {
		HMACKey hmacKey = createHMACKey(key, keyOffset, keyLen);
		mHMACSignature.init(hmacKey, Signature.MODE_VERIFY);
		return mHMACSignature.verify(data, dataOffset, dataLen, mac, macOffset, macLen);
	}

	@Override
	public boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen,
									  byte[] pubKey, short pubKeyOffset, short pubKeyLen) {
		if(certLen <= 0 || cert[0] != 0x30) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short tbsStart = 0;
		for(short i = (short) (certOffset + 1); i < (short)(certOffset + 5); i++) {
			if(cert[i] == 0x30) {
				tbsStart = i;
				break;
			}
		}
		if(tbsStart == 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short tbsLen;
		if(cert[tbsStart + 1] == (byte)0x81) {
			tbsLen = (short)(cert[tbsStart + 2] & 0x00FF);
			tbsLen += 3;
		} else if(cert[tbsStart + 1] == (byte)0x82) {
			tbsLen = Util.getShort(cert, (short) (tbsStart + 2));
			tbsLen += 4;
		} else {
			tbsLen = (short)(cert[tbsStart + 1] & 0x00FF);
			tbsLen += 2;
		}

		short signSeqStart = (short)(tbsStart + tbsLen + (byte)12/*OID TAG*/);
		if(cert[signSeqStart] != 0x03 && cert[(short)(signSeqStart + (byte)2)] != 0x00) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		byte signLen = (byte)(cert[signSeqStart + (byte)1] - (byte)1);//Actual signature Bit string starts after 0x00. signature len expected around 70-72

		ECPublicKey publicKey = (ECPublicKey)ecKeyPair.getPublic();
		Secp256r1.configureECKeyParameters(publicKey);
		publicKey.setW(pubKey, pubKeyOffset, pubKeyLen);
		signerWithSha256.init(publicKey, Signature.MODE_VERIFY);
		return signerWithSha256.verify(cert, tbsStart, tbsLen, cert, (short) (certOffset + certLen - signLen), signLen);
	}
}
