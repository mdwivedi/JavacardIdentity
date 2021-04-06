package android.security.jcic;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class JCICStoreApplet extends Applet implements ExtendedLength {

    // Version identifier of this Applet
    public static final byte[] VERSION = { (byte) 0x00, (byte) 0x02, (byte) 0x00 };

    private final CBORDecoder mCBORDecoder;

    private final CBOREncoder mCBOREncoder;
    
    private final JCICProvisioning mProvisioning;
    
    private final JCICPresentation mPresentation;

    private final APDUManager mAPDUManager;

    public JCICStoreApplet(CryptoProvider cryptoProvider) {
        mCBORDecoder = new CBORDecoder();
        
        mCBOREncoder = new CBOREncoder();

        mAPDUManager = new APDUManager((byte) (CryptoManager.AES_GCM_IV_SIZE + cryptoProvider.getGcmTagLen()));

        CryptoManager cryptoManager = new CryptoManager(mAPDUManager, cryptoProvider/*, mAccessControlManager,*/);
    	
		mProvisioning = new JCICProvisioning(cryptoManager, mAPDUManager, mCBORDecoder, mCBOREncoder);
		
		mPresentation = new JCICPresentation(cryptoManager, mAPDUManager, mCBORDecoder, mCBOREncoder);
		
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCICStoreApplet(new DummyCryptoProvider()).register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

	public void process(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();

        if (!mAPDUManager.process(apdu)) {
            return;
        }


        if (this.selectingApplet()) {
        	mProvisioning.reset();
        	mPresentation.reset();
            //mAccessControlManager.reset();
            processSelectApplet(apdu);
            return;
        }


        if (apdu.isISOInterindustryCLA()) {
            switch (buf[ISO7816.OFFSET_INS]) {
            // TODO: In future we might want to support standard ISO operations (select, get
            // data, etc.).

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
            }
        } else {
            switch (buf[ISO7816.OFFSET_INS]) {
            case ISO7816.INS_ICS_GET_VERSION:
                processGetVersion();
                break;
            case ISO7816.INS_ICS_PING:
                processPing();
                break;
            case ISO7816.INS_ICS_CREATE_CREDENTIAL:
            case ISO7816.INS_ICS_GET_ATTESTATION_CERT:
            case ISO7816.INS_ICS_START_PERSONALIZATION:
            case ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE:
            case ISO7816.INS_ICS_BEGIN_ADD_ENTRY:
            case ISO7816.INS_ICS_BEGIN_ADD_ENTRY_VALUE:
            case ISO7816.INS_ICS_FINISH_ADDING_ENTRIES:
            case ISO7816.INS_ICS_FINISH_GET_CREDENTIAL_DATA:
            	mProvisioning.processAPDU();
            	break;
            case ISO7816.INS_ICS_TEST_CBOR:
                //processTestCBOR();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } 

        mAPDUManager.sendAll();
	}

    /**
     * Process the select command and return hardware configuration in the select
     * applet command.
     */
    private void processSelectApplet(APDU apdu){
        mAPDUManager.setOutgoing();
        byte[] outBuff = mAPDUManager.getSendBuffer();
        Util.setShort(outBuff, (short) 0, (short) apdu.getBuffer().length);
        Util.setShort(outBuff, (short) 2, APDUManager.MAXCHUNKSIZE);
        Util.setShort(outBuff, (short) 4, CryptoManager.getAESKeySize());

        mAPDUManager.setOutgoingLength((short) 6);
        mAPDUManager.sendAll();
    }

    /**
     * Process incoming PING requests.
     */
    private void processPing() {
        final byte[] inBuffer = mAPDUManager.getReceiveBuffer();
        
        short pingType = Util.getShort(inBuffer, ISO7816.OFFSET_P1);

        if (pingType == 0) {
            // Do nothing
        } else if (pingType == 1) {
            // Respond with incoming data
            final short lc = mAPDUManager.receiveAll();
            final short le = mAPDUManager.setOutgoing();
            final byte[] outBuffer = mAPDUManager.getSendBuffer();
            
            short outLen = Util.arrayCopyNonAtomic(inBuffer, mAPDUManager.getOffsetIncomingData(), outBuffer, (short)0, ICUtil.min(lc, le));
            
            mAPDUManager.setOutgoingLength(outLen);
        }
    }
    
    /**
     * Process the GET VERSION command and return the current Applet version
     */
    private void processGetVersion() {
        final byte[] inBuffer = mAPDUManager.getReceiveBuffer();

        if (Util.getShort(inBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short le = mAPDUManager.setOutgoing();
        final byte[] outBuffer = mAPDUManager.getSendBuffer();

        if (le < (short) VERSION.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short outLength = Util.arrayCopyNonAtomic(VERSION, (short) 0, outBuffer, (short) 0, (short) VERSION.length);

        mAPDUManager.setOutgoingLength(outLength);
    }
    
}
