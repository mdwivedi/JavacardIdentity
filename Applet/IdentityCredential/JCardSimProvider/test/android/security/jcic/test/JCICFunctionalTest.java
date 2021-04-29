package android.security.jcic.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.iot.cbor.CborByteString;
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
	public void hardwareInformation() {
		HardwareInfo hardwareInfo = TestUtils.getHardwareInfo(simulator);
		Assert.assertNotNull(hardwareInfo);
		Assert.assertTrue("credentialStoreName : " + hardwareInfo.credentialStoreName, hardwareInfo.credentialStoreName.length() > 0);
		Assert.assertTrue("credentialStoreAuthorName : " + hardwareInfo.credentialStoreAuthorName, hardwareInfo.credentialStoreAuthorName.length() > 0);
		Assert.assertTrue("dataChunkSize : " + hardwareInfo.dataChunkSize, hardwareInfo.dataChunkSize >= 256);
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

	    TestProfile testProfile = new TestProfile(2, TestData.testReaderCertificate1, true, 1);
	    Assert.assertTrue(TestUtils.addAccessControlProfiles(simulator, testProfile));

	}

	@Test
	public void verifyOneProfileAndEntryPass() {
		HardwareInfo hardwareInfo = TestUtils.getHardwareInfo(simulator);
		Assert.assertNotNull(hardwareInfo);
		
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl", 1, new int[] {1}, 185 + TestData.testReaderCertificate1.length);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	    
	    TestProfile testProfile = new TestProfile(1, TestData.testReaderCertificate1, true, 1);
	    Assert.assertTrue(TestUtils.addAccessControlProfiles(simulator, testProfile));

	    TestEntryData entryData = new TestEntryData("Name Space", "Last name", "Turing", new int[] {1});
	    Assert.assertTrue(TestUtils.addEntry(simulator, hardwareInfo.dataChunkSize, entryData));
	    
	    Assert.assertTrue(TestUtils.finishAddingEntries(simulator));
	    
	    Assert.assertTrue(TestUtils.finishGetCredentialData(simulator, "org.iso.18013-5.2019.mdl"));
	}

	@Test
	public void verifyManyProfilesAndEntriesPass() {
		HardwareInfo hardwareInfo = TestUtils.getHardwareInfo(simulator);
		Assert.assertNotNull(hardwareInfo);
		
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));
	    TestProfile[] testProfiles = {new TestProfile(1, TestData.testReaderCertificate1, true, 1), 
	    								new TestProfile(2, TestData.testReaderCertificate2, true, 2)};

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl",
	    																testProfiles.length,
	    																new int[] {1, 3, 1, 1, 2},
	    																/*753 + 492/*753 + 524268*/525021 + TestData.testReaderCertificate1.length + TestData.testReaderCertificate2.length);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	    
	    for(TestProfile testProfile: testProfiles) {
	    	Assert.assertTrue(TestUtils.addAccessControlProfiles(simulator, testProfile));
	    }

	    TestEntryData []entries = {new TestEntryData("Name Space 1", "Last name", "Turing", new int[] {1, 2}),
	    					new TestEntryData("Name Space2", "Home address", "Maida Vale, London, England", new int[] {1}),
	    					new TestEntryData("Name Space2", "Work address", "Maida Vale2, London, England", new int[] {2}),
	    					new TestEntryData("Name Space2", "Trailer address", "Maida, London, England", new int[] {1}),
	    					new TestEntryData("Image", "Portrait image", TestData.getImageData(), new int[] {1}),
	    					new TestEntryData("Image2", "Work image", TestData.getImageData(), new int[] {1, 2}),
	    					new TestEntryData("Name Space3", "xyzw", "random stuff", new int[] {1, 2}),
	    					new TestEntryData("Name Space3", "Something", "Some string", new int[] {2})};
	    for(TestEntryData entryData : entries) {
	    	Assert.assertTrue(TestUtils.addEntry(simulator, hardwareInfo.dataChunkSize, entryData));
	    }
	    
	    Assert.assertTrue(TestUtils.finishAddingEntries(simulator));
	    
	    Assert.assertTrue(TestUtils.finishGetCredentialData(simulator, "org.iso.18013-5.2019.mdl"));
	}

	@Test
	public void verifyEmptyNameSpaceMixedWithNonEmptyWorks() {
		HardwareInfo hardwareInfo = TestUtils.getHardwareInfo(simulator);
		Assert.assertNotNull(hardwareInfo);
		
		Assert.assertTrue(TestUtils.setupWritableCredential(simulator, false /* testCredential */));
	    TestProfile[] testProfiles = {new TestProfile(0, TestData.testReaderCertificate1, false, 0), 
	    								new TestProfile(1, TestData.testReaderCertificate2, true, 1), 
	    								new TestProfile(2, new byte[0], false, 0)};

	    PersonalizationData personalizationData = new PersonalizationData("org.iso.18013-5.2019.mdl",
	    																testProfiles.length,
	    																new int[] {2, 2},
	    																377 + TestData.testReaderCertificate1.length + TestData.testReaderCertificate2.length);
	    Assert.assertTrue(TestUtils.startPersonalization(simulator, personalizationData));
	    
	    for(TestProfile testProfile: testProfiles) {
	    	Assert.assertTrue(TestUtils.addAccessControlProfiles(simulator, testProfile));
	    }

	    TestEntryData []entries = {new TestEntryData("", "t name", "Turing", new int[] {2}),
	    					new TestEntryData("", "Birth", "19120623", new int[] {2}),
	    					new TestEntryData("Name Space", "Last name", "Turing", new int[] {0, 1}),
	    					new TestEntryData("Name Space", "Birth date", "19120623", new int[] {0, 1})};
	    for(TestEntryData entryData : entries) {
	    	Assert.assertTrue(TestUtils.addEntry(simulator, hardwareInfo.dataChunkSize, entryData));
	    }
	    
	    Assert.assertTrue(TestUtils.finishAddingEntries(simulator));
	    
	}
}
