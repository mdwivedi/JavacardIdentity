package android.security.jcic;

import android.security.jcic.JCICStoreApplet;

public class JCardSimJCICStoreApplet extends JCICStoreApplet {
	
	private JCardSimJCICStoreApplet() {
		super(new JCardSimCryptoProvider());
	}

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCardSimJCICStoreApplet().register();
    }

}
