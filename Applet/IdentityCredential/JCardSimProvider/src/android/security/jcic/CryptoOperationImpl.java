package android.security.jcic;

import com.android.javacard.keymaster.KMOperation;

public class CryptoOperationImpl implements ICryptoOperation {
	KMOperation kmOperation;
	
	public CryptoOperationImpl(KMOperation kmOperation) {
		this.kmOperation = kmOperation;
	}

	@Override
	public short sign(byte[] inputDataBuf, short inputDataStart, short inputDataLength, byte[] signBuf,
			short signStart) {
		return kmOperation.sign(inputDataBuf, inputDataStart, inputDataLength, signBuf, signStart);
	}

}
