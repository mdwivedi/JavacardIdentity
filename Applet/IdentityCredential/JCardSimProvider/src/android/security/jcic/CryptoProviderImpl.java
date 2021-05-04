package android.security.jcic;

import com.android.javacard.keymaster.KMJCardSimulator;
import com.android.javacard.keymaster.KMOperation;
import com.android.javacard.keymaster.KMSEProvider;
import com.android.javacard.keymaster.KMType;

public class CryptoProviderImpl implements ICryptoProvider{
	KMSEProvider kmSEProvider;
	
	CryptoProviderImpl() {
		kmSEProvider = new KMJCardSimulator();
	}

	@Override
	public void createECKey(byte[] privKeyBuf, short privKeyStart, short privKeyMaxLength,
			byte[] pubModBuf, short pubModStart, short pubModMaxLength, short[] lengths) {
		kmSEProvider.createAsymmetricKey(KMType.EC, privKeyBuf, privKeyStart, privKeyMaxLength,
				pubModBuf, pubModStart, pubModMaxLength, lengths);
	}

	@Override
	public ICryptoOperation initECSignWithNoDigestOperation(byte[] privKeyBuf, short privKeyStart,
			short privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength) {

    	KMOperation signer = kmSEProvider.initAsymmetricOperation(KMType.SIGN, KMType.EC,  KMType.PADDING_NONE , KMType.DIGEST_NONE,
    			privKeyBuf, privKeyStart, privKeyLength, //Private key
    			pubModBuf, pubModStart, pubModLength); //Public key
    	
		return new CryptoOperationImpl(signer);
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

}
