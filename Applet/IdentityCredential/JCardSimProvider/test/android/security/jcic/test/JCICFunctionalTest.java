package android.security.jcic.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.iot.cbor.CborArray;
import com.google.iot.cbor.CborInteger;
import com.google.iot.cbor.CborTextString;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import android.security.jcic.CBORDecoder;
import android.security.jcic.CBOREncoder;
import android.security.jcic.ISO7816;
import android.security.jcic.JCardSimJCICStoreApplet;
import javacard.framework.AID;
import javacard.framework.Util;

public class JCICFunctionalTest {
	private CardSimulator simulator;

	public JCICFunctionalTest() {
		simulator =  new CardSimulator();
	}
	
	@Before
	public void init() {
	    // Create simulator
	    AID appletAID = AIDUtil.create("A00000006203020C010101");
	    simulator.installApplet(appletAID, JCardSimJCICStoreApplet.class);
	    // Select applet
	    simulator.selectApplet(appletAID);
	}

	@After
	public void cleanUp() {
		AID appletAID = AIDUtil.create("A00000006203020C010101");
		// Delete i.e. uninstall applet
		simulator.deleteApplet(appletAID);
	}

	@Test
	public void testCreateCredential() {
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x00, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());

	    //test credential
		apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x01, (byte) 0x00});
	    response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());

	    //Wrong P2 value
		apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x02, (byte) 0x00});
	    response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x6A86, response.getSW());
	    
	}

	@Test
	public void testStartPerosanalization() {
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x00, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(5));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {2, 4}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    apdu = encodeApdu(ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	}

	private CommandAPDU encodeApdu(byte ins, byte p1, byte p2, byte[] inBuff, short offset, short length) {
		short apduLength = 0;
		byte[] buf = new byte[2500];
		buf[0] = (byte) 0x80; apduLength++;
		buf[1] = ins; apduLength++;
		buf[2] = p1; apduLength++;
		buf[3] = p2; apduLength++;
		buf[4] = 0; apduLength++;
		if(inBuff != null && length > 0) {
			Util.setShort(buf, (short) 5, length);  apduLength += 2;
			Util.arrayCopyNonAtomic(inBuff, (short) 0, buf, (short) apduLength, (short) length);
			 apduLength += length;
		}
		byte[] apdu = new byte[apduLength];
		Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0, (short) apduLength);
		return new CommandAPDU(apdu);
	}

}
