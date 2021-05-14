package android.security.jcic.test;

import java.util.Iterator;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Assert;

import com.google.iot.cbor.CborArray;
import com.google.iot.cbor.CborByteString;
import com.google.iot.cbor.CborInteger;
import com.google.iot.cbor.CborObject;
import com.google.iot.cbor.CborParseException;
import com.google.iot.cbor.CborSimple;
import com.google.iot.cbor.CborTextString;
import com.licel.jcardsim.smartcardio.CardSimulator;

import android.security.jcic.ISO7816;
import javacard.framework.Util;

public class TestUtils {

	public static HardwareInfo getHardwareInfo(CardSimulator simulator) {
		HardwareInfo hardwareInfo = null;
		
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_GET_HARDWARE_INFO, (byte) 0x00, (byte) 0x00, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    Assert.assertEquals(0x9000, response.getSW());
	    try {
	    	CborArray hardwareInfoArray = (CborArray)CborArray.createFromCborByteArray(response.getData(), (short)0, response.getData().length);
	    	hardwareInfo = new HardwareInfo();
	    	Iterator<CborObject> itr = hardwareInfoArray.iterator();
	    	
	    	hardwareInfo.credentialStoreName = itr.next().toJavaObject().toString();
	    	hardwareInfo.credentialStoreAuthorName = itr.next().toJavaObject().toString();
	    	hardwareInfo.dataChunkSize = (Integer)itr.next().toJavaObject();
	    	hardwareInfo.isDirectAccess = (Boolean)itr.next().toJavaObject();
	    	Object obj = itr.next().toJavaObject();
	    	if(obj != null && obj instanceof String[]) {
	    		hardwareInfo.supportedDocTypes = (String[])obj;
	    	}
	    } catch (CborParseException e) {
	    	Assert.fail();
	    }
	    return hardwareInfo;
	}
	
	public static boolean setupWritableCredential(CardSimulator simulator, boolean testCredential) {
		byte p2 = testCredential ? (byte)0x01 : (byte)0x00;
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_PROVISIONING_INIT, (byte) 0x00, p2, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    return (0x9000 == response.getSW());
	}

	public static AttestationData getAttestationCertificate(CardSimulator simulator, byte[] challenge, byte[] applicationId) {
		AttestationData attestationData = null;

		CborArray cborArray = CborArray.create();
		cborArray.add(CborByteString.create(challenge));
		cborArray.add(CborByteString.create(applicationId));
		byte[] inBuff = cborArray.toCborByteArray();

		CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_CREATE_CREDENTIAL_KEY, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
		ResponseAPDU response = simulator.transmitCommand(apdu);
		Assert.assertEquals(0x9000, response.getSW());
		System.out.println("getAttestationCertificate Response : ");
		for(int i = 0; i < response.getBytes().length; i++) {
			System.out.print(String.format("%02X", response.getBytes()[i]));
		}
		System.out.println();
		try {
			CborArray attestationCertArray = (CborArray)CborArray.createFromCborByteArray(response.getData(), (short)0, response.getData().length);
			attestationData = new AttestationData();
			Iterator<CborObject> itr = attestationCertArray.iterator();

			attestationData.attestationChallenge = challenge;
			attestationData.attestationApplicationId = applicationId;
			//attestationData.attestationCertificate =
			//TODO get attestation certificates
		} catch (CborParseException e) {
			Assert.fail();
		}
		return attestationData;
	}

	public static boolean startPersonalization(CardSimulator simulator, PersonalizationData personalizationData) {
	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create(personalizationData.docType));
	    cborArray.add(CborInteger.create(personalizationData.accessControlProfileCounts));
	    cborArray.add(CborArray.createFromJavaObject(personalizationData.entryCounts));
	    cborArray.add(CborInteger.create(personalizationData.expectedProofOfProvisioingSize));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    return (0x9000 == response.getSW());
	}

	public static boolean addAccessControlProfiles(CardSimulator simulator, TestProfile profileData) {

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborInteger.create(profileData.id)); //int_8 : id
	    cborArray.add(profileData.userAuthenticationRequired ? CborSimple.TRUE : CborSimple.FALSE); //boolean : userAuthenticationRequired
	    cborArray.add(CborInteger.create(profileData.timeoutMillis)); //int_64 : timeoutMilis
	    cborArray.add(CborInteger.create(profileData.secureUserId)); //int_64 : secureUserId
    	cborArray.add(CborByteString.create(profileData.readerCertificate)); // byteString : readerCretificate
	    byte[] inBuff = cborArray.toCborByteArray();
	    CommandAPDU apdu = null;
	    ResponseAPDU response = null;
	    for (short offset = 0; offset < inBuff.length; offset += TestData.MAX_APDU_BUFF_SIZE) {
	    	boolean isChainingRequired = ((short)(offset + TestData.MAX_APDU_BUFF_SIZE) <= inBuff.length);
	    	short length = isChainingRequired ? (short)(TestData.MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
		    apdu = TestUtils.encodeApdu(isChainingRequired, ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length);
			response = simulator.transmitCommand(apdu);
		    Assert.assertEquals(0x9000, response.getSW());
	    }
	    System.out.println("addAccessControlProfile Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    return (0x9000 == response.getSW());
	}

	public static boolean addEntry(CardSimulator simulator, int chunkSize, TestEntryData entryData) {
		int entryValueLenght = entryData.valueCbor.length;
		
		CborArray additionalDataCbor = CborArray.create();
		additionalDataCbor.add(CborTextString.create(entryData.nameSpace));
		additionalDataCbor.add(CborTextString.create(entryData.name));
		additionalDataCbor.add(CborArray.createFromJavaObject(entryData.profileIds));
		additionalDataCbor.add(CborInteger.create(entryValueLenght));
	    byte[] inBuff = additionalDataCbor.toCborByteArray();

	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_BEGIN_ADD_ENTRY, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    System.out.println("addEntry Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    if(0x9000 != response.getSW()) {
	    	return false;
	    }

		additionalDataCbor = CborArray.create();
		additionalDataCbor.add(CborTextString.create(entryData.nameSpace));
		additionalDataCbor.add(CborTextString.create(entryData.name));
		additionalDataCbor.add(CborArray.createFromJavaObject(entryData.profileIds));
		
		int noOfChunks = (entryValueLenght + chunkSize - 1) / chunkSize;
	    int pos = 0;
	    int processedLength = 0;
	    for (int n = 0; n < noOfChunks; n++) {
	        int size = entryValueLenght - pos;
	        if (size > chunkSize) {
	            size = chunkSize;
	        }
			CborArray cborArray = CborArray.create();
			cborArray.add(additionalDataCbor);
			cborArray.add(CborByteString.create(entryData.valueCbor, pos, size));
		    inBuff = cborArray.toCborByteArray();

		    processedLength += size;
		    
		    for (short offset = 0; offset < inBuff.length; offset += TestData.MAX_APDU_BUFF_SIZE) {
		    	boolean isChainingRequired = ((short)(offset + TestData.MAX_APDU_BUFF_SIZE) <= inBuff.length);
		    	short length = isChainingRequired ? (short)(TestData.MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
			    apdu = TestUtils.encodeApdu(isChainingRequired, ISO7816.INS_ICS_ADD_ENTRY_VALUE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length);
				response = simulator.transmitCommand(apdu);
			    Assert.assertEquals(0x9000, response.getSW());
		    }
	        pos += chunkSize;
	    }
	    System.out.println("entryValueLenght : " + entryValueLenght + " & processedLength : " + processedLength);
	    
	    System.out.println("addEntryValue Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    return (0x9000 == response.getSW());
	}

	public static boolean finishAddingEntries(CardSimulator simulator) {
		CommandAPDU apdu = new CommandAPDU(new byte[] {(byte) 0x80, ISO7816.INS_ICS_FINISH_ADDING_ENTRIES, (byte) 0x00, 0x00, (byte) 0x00});
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    System.out.println("finishAddingEntries Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    return (0x9000 == response.getSW());
	}

	public static boolean finishGetCredentialData(CardSimulator simulator, String docType) {
		CborArray cborArray = CborArray.create();
		cborArray.add(CborTextString.create(docType));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_FINISH_GET_CREDENTIAL_DATA, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    System.out.println("finishGetCredentialData Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    return (0x9000 == response.getSW());
	}

	public static CommandAPDU encodeApdu(boolean isChaining, byte ins, byte p1, byte p2, byte[] inBuff, short offset, short length) {
		short apduLength = 0;
		byte[] buf = new byte[2500];
		buf[0] = (byte)((byte)0x80 | (isChaining ? (byte) 0x10 : (byte) 0x00)); apduLength++;
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
