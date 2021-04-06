package android.security.jcic;

public class JCICPresentation {

	private CryptoManager mCryptoManager;

    // Reference to the internal APDU manager instance
    private final APDUManager mAPDUManager;
    
    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;

    
	public JCICPresentation(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
		mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
	}

	public void reset() {
		mCryptoManager.reset();
		mAPDUManager.reset();
	}
}
