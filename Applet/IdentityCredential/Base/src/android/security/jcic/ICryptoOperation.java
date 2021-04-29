package android.security.jcic;

public interface ICryptoOperation {

	  // Used for finishing signing operations.
	  short sign(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
	      byte[] signBuf, short signStart);

}
