package android.security.jcic.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.smartcardio.CardSimulator;

import android.security.jcic.ISO7816;
import javacard.framework.Util;

public class TestUtils {

	public static boolean setupWritableCredential(CardSimulator simulator, boolean testCredential) {
		byte p2 = testCredential ? (byte)0x01 : (byte)0x00;
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, p2, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    if(0x9000 == response.getSW()) {
	    	return true;
	    } else {
	    	return false;
	    }

	}

	public static CommandAPDU encodeApdu(boolean isChaining, byte ins, byte p1, byte p2, byte[] inBuff, short offset, short length) {
		short apduLength = 0;
		byte[] buf = new byte[2500];
		buf[0] = isChaining ? (byte) 0x58 : (byte) 0x80; apduLength++;
		buf[1] = ins; apduLength++;
		buf[2] = p1; apduLength++;
		buf[3] = p2; apduLength++;
		buf[4] = 0; apduLength++;
		if(inBuff != null && length > 0 && length <= TestData.MAX_APDU_BUFF_SIZE) {
			Util.setShort(buf, (short) 5, length);  apduLength += 2;
			Util.arrayCopyNonAtomic(inBuff, (short) offset, buf, (short) apduLength, (short) length);
			 apduLength += length;
		}
		byte[] apdu = new byte[apduLength + 2];
		Util.setShort(apdu, (short)(apduLength), (short)0);
		Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0, (short) (apduLength + 2));
		return new CommandAPDU(apdu);
	}

}
