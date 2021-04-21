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
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, true /* testCredential */));

	    //Wrong P2 value
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_CREATE_CREDENTIAL, (byte) 0x00, (byte) 0x02, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertNotEquals(0x9000, response.getSW());
	}

	@Test
	public void verifyStartPersonalization() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(5));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {2, 4}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    response = simulator.transmitCommand(apdu);
	    Assert.assertNotEquals(0x9000, response.getSW());
	}

	@Test
	public void verifyStartPersonalizationMin() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(1));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {1, 1}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	}

	@Test
	public void verifyStartPersonalizationOne() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(1));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {1}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	}

	@Test
	public void verifyStartPersonalizationLarge() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(25));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {255}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	}

	@Test
	public void testAddAccessControlProfile() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(5));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {2, 4}));
	    cborArray.add(CborInteger.create(123456));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    // Call personalization again to check if repeat call is allowed.
	    cborArray = CborArray.create();
	    cborArray.add(CborInteger.create(2)); //int_8 : id
	    cborArray.add(CborSimple.create(21)); //boolean : userAuthenticationRequired
	    cborArray.add(CborInteger.create(1)); //int_64 : timeoutMilis
	    cborArray.add(CborInteger.create(66)); //int_64 : secureUserId
	    cborArray.add(CborByteString.create(TestData.testReaderCertificate)); // byteString : readerCretificate
	    inBuff = cborArray.toCborByteArray();
	    
	    for (short offset = 0; offset < inBuff.length; offset += TestData.MAX_APDU_BUFF_SIZE) {
		    if(inBuff != null && inBuff.length > TestData.MAX_APDU_BUFF_SIZE) {
		    	boolean isLast = (short)(offset + TestData.MAX_APDU_BUFF_SIZE) >= inBuff.length;
		    	short length = !isLast ? (short)(TestData.MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
			    apdu = TestUtils.encodeApdu(!isLast, ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length);
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
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create("org.iso.18013-5.2019.mdl"));
	    cborArray.add(CborInteger.create(1));
	    cborArray.add(CborArray.createFromJavaObject(new int[] {1}));
	    cborArray.add(CborInteger.create(185 + TestData.testReaderCertificate.length));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    
	    // Call personalization again to check if repeat call is allowed.
	    cborArray = CborArray.create();
	    cborArray.add(CborInteger.create(1)); //int_8 : id
	    cborArray.add(CborSimple.create(21)); //boolean : userAuthenticationRequired
	    cborArray.add(CborInteger.create(1)); //int_64 : timeoutMilis
	    cborArray.add(CborInteger.create(66)); //int_64 : secureUserId
	    cborArray.add(CborByteString.create(TestData.testReaderCertificate)); // byteString : readerCretificate
	    inBuff = cborArray.toCborByteArray();
	    
	    for (short offset = 0; offset < inBuff.length; offset += TestData.MAX_APDU_BUFF_SIZE) {
		    if(inBuff != null && inBuff.length > TestData.MAX_APDU_BUFF_SIZE) {
		    	boolean isLast = (short)(offset + TestData.MAX_APDU_BUFF_SIZE) >= inBuff.length;
		    	short length = !isLast ? (short)(TestData.MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
			    apdu = TestUtils.encodeApdu(!isLast, ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length);
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

	    apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_BEGIN_ADD_ENTRY, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    System.out.println("Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    Assert.assertEquals(0x9000, response.getSW());
	}

}
