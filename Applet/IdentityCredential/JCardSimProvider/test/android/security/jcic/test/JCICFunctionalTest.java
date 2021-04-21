package android.security.jcic.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.iot.cbor.CborArray;
import com.google.iot.cbor.CborByteString;
import com.google.iot.cbor.CborInteger;
import com.google.iot.cbor.CborSimple;
import com.google.iot.cbor.CborTextString;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import android.security.jcic.ISO7816;
import android.security.jcic.JCardSimJCICStoreApplet;
import javacard.framework.AID;
import javacard.framework.Util;

public class JCICFunctionalTest {
	private CardSimulator simulator;
	
	private static final short MAX_APDU_BUFF_SIZE = (short)234;
	
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
	    
	    apdu = encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    // Call personalization again to check if repeat call is allowed.
	    cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(7));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {2, 4}));
	    cborArray.add(CborInteger.create(123456));
	    inBuff = cborArray.toCborByteArray();
	    
	    apdu = encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    
	    // TODO Second call to startPersonalization should have failed.
	    Assert.assertEquals(0x9000, response.getSW());
	    
	}

	@Test
	public void testAddAccessControlProfile() {
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x01, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(5));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {5, 6}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    apdu = encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    // Call personalization again to check if repeat call is allowed.
	    cborArray = CborArray.create();
	    cborArray.add(CborInteger.create(2)); //int_8 : id
	    cborArray.add(CborSimple.create(21)); //boolean : userAuthenticationRequired
	    cborArray.add(CborInteger.create(1)); //int_64 : timeoutMilis
	    cborArray.add(CborInteger.create(66)); //int_64 : secureUserId
	    cborArray.add(CborByteString.create(TestData.testReaderCertificate)); // byteString : readerCretificate
	    inBuff = cborArray.toCborByteArray();
	    
	    for (short offset = 0; offset < inBuff.length; offset += MAX_APDU_BUFF_SIZE) {
		    if(inBuff != null && inBuff.length > MAX_APDU_BUFF_SIZE) {
		    	boolean isLast = (short)(offset + MAX_APDU_BUFF_SIZE) >= inBuff.length;
		    	short length = !isLast ? (short)(MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
			    apdu = encodeApdu(!isLast, ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length, (short)inBuff.length);
			}
		    response = simulator.transmitCommand(apdu);
		    Assert.assertEquals(0x9000, response.getSW());
	    }
	    System.out.println("Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    Assert.assertEquals(0x9000, response.getSW());
	    
	}

	@Test
	public void verifyOneProfileAndEntryPass() {
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x01, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(1));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {1}));
	    cborArray.add(CborInteger.create(185 + TestData.testReaderCertificate.length));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    apdu = encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    // Call personalization again to check if repeat call is allowed.
	    cborArray = CborArray.create();
	    cborArray.add(CborInteger.create(1)); //int_8 : id
	    cborArray.add(CborSimple.create(21)); //boolean : userAuthenticationRequired
	    cborArray.add(CborInteger.create(1)); //int_64 : timeoutMilis
	    cborArray.add(CborInteger.create(66)); //int_64 : secureUserId
	    cborArray.add(CborByteString.create(TestData.testReaderCertificate)); // byteString : readerCretificate
	    inBuff = cborArray.toCborByteArray();
	    
	    for (short offset = 0; offset < inBuff.length; offset += MAX_APDU_BUFF_SIZE) {
		    if(inBuff != null && inBuff.length > MAX_APDU_BUFF_SIZE) {
		    	boolean isLast = (short)(offset + MAX_APDU_BUFF_SIZE) >= inBuff.length;
		    	short length = !isLast ? (short)(MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
			    apdu = encodeApdu(!isLast, ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length, (short)inBuff.length);
			}
		    response = simulator.transmitCommand(apdu);
		    Assert.assertEquals(0x9000, response.getSW());
	    }
	    System.out.println("Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    Assert.assertEquals(0x9000, response.getSW());
	    

	    cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("Name Space"));
	    cborArray.add(CborTextString.create("Last name"));
	    cborArray.add(CborInteger.create(65535));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {1}));
	    inBuff = cborArray.toCborByteArray();

	    apdu = encodeApdu(false, ISO7816.INS_ICS_BEGIN_ADD_ENTRY, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    System.out.println("Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    Assert.assertEquals(0x9000, response.getSW());
	}

	private CommandAPDU encodeApdu(boolean isChaining, byte ins, byte p1, byte p2, byte[] inBuff, short offset, short length, short totalLength) {
		short apduLength = 0;
		byte[] buf = new byte[2500];
		buf[0] = isChaining ? (byte) 0x58 : (byte) 0x80; apduLength++;
		buf[1] = ins; apduLength++;
		buf[2] = p1; apduLength++;
		buf[3] = p2; apduLength++;
		buf[4] = 0; apduLength++;
		if(inBuff != null && length > 0 && length <= MAX_APDU_BUFF_SIZE) {
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
