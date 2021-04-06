package android.security.jcic;

import android.security.jcic.CryptoProvider;

public class JCardSimCryptoProvider implements CryptoProvider {

	public short getGcmTagLen() {
		return 10;
	}

}
