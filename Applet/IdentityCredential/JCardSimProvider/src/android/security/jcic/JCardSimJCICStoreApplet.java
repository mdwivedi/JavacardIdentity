package android.security.jcic;

import com.android.javacard.keymaster.KMJCardSimulator;

public class JCardSimJCICStoreApplet extends JCICStoreApplet {
	
	private JCardSimJCICStoreApplet() {
		super(new KMJCardSimulator());
	}

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCardSimJCICStoreApplet().register();
    }

}
