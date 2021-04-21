package android.security.jcic;

import org.globalplatform.upgrade.Element;

import com.android.javacard.keymaster.KMAttestationCert;
import com.android.javacard.keymaster.KMAttestationKey;
import com.android.javacard.keymaster.KMMasterKey;
import com.android.javacard.keymaster.KMOperation;
import com.android.javacard.keymaster.KMPreSharedKey;

import javacard.security.Key;
import javacardx.crypto.Cipher;

public class DummyCryptoProvider implements com.android.javacard.keymaster.KMSEProvider {


	public void init(Cipher cipher, Key key, byte mode) {
		// TODO Auto-generated method stub
		
	}

	public void update(byte[] buff, short buffOffset, short length, byte[] outBuff, short outOffset) {
		// TODO Auto-generated method stub
		
	}

	public void doFinal(byte[] buff, short buffOffset, short length, byte[] outBuff, short outOffset, short outLength) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onSave(Element ele) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onRestore(Element ele) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public short getBackupPrimitiveByteCount() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short getBackupObjectCount() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short createSymmetricKey(byte alg, short keysize, byte[] buf, short startOff) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void createAsymmetricKey(byte alg, byte[] privKeyBuf, short privKeyStart, short privKeyMaxLength,
			byte[] pubModBuf, short pubModStart, short pubModMaxLength, short[] lengths) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean importSymmetricKey(byte alg, short keysize, byte[] buf, short startOff, short length) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean importAsymmetricKey(byte alg, byte[] privKeyBuf, short privKeyStart, short privKeyLength,
			byte[] pubModBuf, short pubModStart, short pubModLength) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void newRandomNumber(byte[] num, short offset, short length) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addRngEntropy(byte[] num, short offset, short length) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void getTrueRandomNumber(byte[] num, short offset, short length) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public short aesGCMEncrypt(byte[] aesKey, short aesKeyStart, short aesKeyLen, byte[] data, short dataStart,
			short dataLen, byte[] encData, short encDataStart, byte[] nonce, short nonceStart, short nonceLen,
			byte[] authData, short authDataStart, short authDataLen, byte[] authTag, short authTagStart,
			short authTagLen) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean aesGCMDecrypt(byte[] aesKey, short aesKeyStart, short aesKeyLen, byte[] encData, short encDataStart,
			short encDataLen, byte[] data, short dataStart, byte[] nonce, short nonceStart, short nonceLen,
			byte[] authData, short authDataStart, short authDataLen, byte[] authTag, short authTagStart,
			short authTagLen) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public short cmacKDF(KMPreSharedKey hmacKey, byte[] label, short labelStart, short labelLen, byte[] context,
			short contextStart, short contextLength, byte[] key, short keyStart) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short hmacSign(byte[] keyBuf, short keyStart, short keyLength, byte[] data, short dataStart,
			short dataLength, byte[] signature, short signatureStart) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short hmacKDF(KMMasterKey masterkey, byte[] data, short dataStart, short dataLength, byte[] signature,
			short signatureStart) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean hmacVerify(byte[] keyBuf, short keyStart, short keyLength, byte[] data, short dataStart,
			short dataLength, byte[] signature, short signatureStart, short signatureLen) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public short rsaDecipherOAEP256(byte[] privExp, short privExpStart, short privExpLength, byte[] modBuffer,
			short modOff, short modLength, byte[] inputDataBuf, short inputDataStart, short inputDataLength,
			byte[] outputDataBuf, short outputDataStart) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short ecSign256(KMAttestationKey ecPrivKey, byte[] inputDataBuf, short inputDataStart, short inputDataLength,
			byte[] outputDataBuf, short outputDataStart) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public KMOperation initSymmetricOperation(byte purpose, byte alg, byte digest, byte padding, byte blockMode,
			byte[] keyBuf, short keyStart, short keyLength, byte[] ivBuf, short ivStart, short ivLength,
			short macLength) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMOperation initAsymmetricOperation(byte purpose, byte alg, byte padding, byte digest, byte[] privKeyBuf,
			short privKeyStart, short privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMAttestationCert getAttestationCert(boolean rsaCert) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void persistPartialCertificateChain(byte[] buf, short offset, short len, short totalLen) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void clearCertificateChain() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public short readCertificateChain(byte[] buf, short offset) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short getCertificateChainLength() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean isBootSignalEventSupported() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isDeviceRebooted() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void clearDeviceBooted(boolean resetBootFlag) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isUpgrading() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public KMMasterKey createMasterKey(short keySizeBits) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMAttestationKey createAttestationKey(byte[] keyData, short offset, short length) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMPreSharedKey createPresharedKey(byte[] keyData, short offset, short length) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMMasterKey getMasterKey() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMAttestationKey getAttestationKey() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KMPreSharedKey getPresharedKey() {
		// TODO Auto-generated method stub
		return null;
	}
}
