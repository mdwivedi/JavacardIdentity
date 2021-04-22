package android.security.jcic.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Assert;

import com.google.iot.cbor.CborArray;
import com.google.iot.cbor.CborByteString;
import com.google.iot.cbor.CborInteger;
import com.google.iot.cbor.CborSimple;
import com.google.iot.cbor.CborTextString;
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

	public static boolean startPersonalization(CardSimulator simulator, PersonalizationData personalizationData) {
	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborTextString.create(personalizationData.docType));
	    cborArray.add(CborInteger.create(personalizationData.accessControlProfileCounts));
	    cborArray.add(CborArray.createFromJavaObject(personalizationData.entryCounts));
	    cborArray.add(CborInteger.create(personalizationData.expectedProofOfProvisioingSize));
	    byte[] inBuff = cborArray.toCborByteArray();
	    
	    CommandAPDU apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_START_PERSONALIZATION, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    ResponseAPDU response = simulator.transmitCommand(apdu);
	    if(0x9000 == response.getSW()) {
	    	return true;
	    } else {
	    	return false;
	    }

	}

	public static boolean addAccessControlProfile(CardSimulator simulator, TestProfile profileData) {

	    CborArray cborArray = CborArray.create();
	    cborArray.add(CborInteger.create(profileData.id)); //int_8 : id
	    cborArray.add(CborSimple.create(profileData.userAuthenticationRequired ? 21 : 20)); //boolean : userAuthenticationRequired
	    cborArray.add(CborInteger.create(profileData.timeoutMillis)); //int_64 : timeoutMilis
	    cborArray.add(CborInteger.create(profileData.secureUserId)); //int_64 : secureUserId
	    cborArray.add(CborByteString.create(TestData.testReaderCertificate)); // byteString : readerCretificate
	    byte[] inBuff = cborArray.toCborByteArray();
	    CommandAPDU apdu = null;
	    ResponseAPDU response = null;
	    for (short offset = 0; offset < inBuff.length; offset += TestData.MAX_APDU_BUFF_SIZE) {
		    if(inBuff != null && inBuff.length > TestData.MAX_APDU_BUFF_SIZE) {
		    	boolean isLast = (short)(offset + TestData.MAX_APDU_BUFF_SIZE) >= inBuff.length;
		    	short length = !isLast ? (short)(TestData.MAX_APDU_BUFF_SIZE) : (short) (inBuff.length - offset);
			    apdu = TestUtils.encodeApdu(!isLast, ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE, (byte) 0x00, (byte) 0x00, inBuff, (short) offset, length);
			}
		    response = simulator.transmitCommand(apdu);
		    Assert.assertEquals(0x9000, response.getSW());
	    }
	    System.out.println("addAccessControlProfile Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
	    if(0x9000 == response.getSW()) {
	    	return true;
	    } else {
	    	return false;
	    }

	}

	public static boolean addEntry(CardSimulator simulator, TestEntryData entryData) {
		CborArray additionDataCbor = CborArray.create();
		additionDataCbor.add(CborTextString.create(entryData.nameSpace));
		additionDataCbor.add(CborTextString.create(entryData.name));
		additionDataCbor.add(CborArray.createFromJavaObject(entryData.profileIds));
		additionDataCbor.add(CborInteger.create(65535));
	    byte[] inBuff = additionDataCbor.toCborByteArray();

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

		additionDataCbor = CborArray.create();
		additionDataCbor.add(CborTextString.create(entryData.nameSpace));
		additionDataCbor.add(CborTextString.create(entryData.name));
		additionDataCbor.add(CborArray.createFromJavaObject(entryData.profileIds));
		CborArray cborArray = CborArray.create();
		cborArray.add(additionDataCbor);
		cborArray.add(CborByteString.create(entryData.valueCbor));
	    inBuff = cborArray.toCborByteArray();

	    apdu = TestUtils.encodeApdu(false, ISO7816.INS_ICS_ADD_ENTRY_VALUE, (byte) 0x00, (byte) 0x00, inBuff, (short) 0, (short) inBuff.length);
	    response = simulator.transmitCommand(apdu);
	    System.out.println("addEntryValue Response : ");
	    for(int i = 0; i < response.getBytes().length; i++) {
	    	System.out.print(String.format("%02X", response.getBytes()[i]));
	    }
	    System.out.println();
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
