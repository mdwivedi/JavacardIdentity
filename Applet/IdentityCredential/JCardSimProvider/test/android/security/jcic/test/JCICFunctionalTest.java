package android.security.jcic.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.iot.cbor.CborTextString;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import android.security.jcic.ISO7816;
import android.security.jcic.JCardSimJCICStoreApplet;
import javacard.framework.AID;

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

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 5, new int[] {2, 4}, 123456);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	    Assert.assertFalse(TestUtils.startPersonalization(simulator, personalizationData));
	}

	@Test
	public void verifyStartPersonalizationMin() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 1, new int[] {1, 1}, 123456);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	}

	@Test
	public void verifyStartPersonalizationOne() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 1, new int[] {1}, 123456);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	}

	@Test
	public void verifyStartPersonalizationLarge() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 25, new int[] {255}, 123456);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	}

	@Test
	public void testAddAccessControlProfile() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 5, new int[] {2, 4}, 123456);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));

	    TestProfile testProfile = new TestProfile(2, TestData.testReaderCertificate, true, 1);
	    Assert.assertTrue(TestUtils.addAccessControlProfile(simulator, testProfile));

	}

	@Test
	public void verifyOneProfileAndEntryPass() {
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 1, new int[] {1}, 185 + TestData.testReaderCertificate.length);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	    
	    TestProfile testProfile = new TestProfile(1, TestData.testReaderCertificate, true, 1);
	    Assert.assertTrue(TestUtils.addAccessControlProfile(simulator, testProfile));

	    TestEntryData entryData = new TestEntryData("Name Space", "Last name", CborTextString.create("Turing").toCborByteArray(), new int[] {1});
	    Assert.assertTrue(TestUtils.addEntry(simulator, entryData));
	}

}
