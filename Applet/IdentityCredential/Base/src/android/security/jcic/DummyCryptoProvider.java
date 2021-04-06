package android.security.jcic;

public class DummyCryptoProvider implements CryptoProvider {

	public short getGcmTagLen() {
		return 10;
	}

}
