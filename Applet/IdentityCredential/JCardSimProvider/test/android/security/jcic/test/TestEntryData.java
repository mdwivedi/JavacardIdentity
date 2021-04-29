package android.security.jcic.test;

import com.google.iot.cbor.CborByteString;
import com.google.iot.cbor.CborConversionException;
import com.google.iot.cbor.CborInteger;
import com.google.iot.cbor.CborObject;
import com.google.iot.cbor.CborSimple;
import com.google.iot.cbor.CborTextString;

public class TestEntryData {
    String nameSpace;
    String name;
    byte[] valueCbor;
    int[] profileIds;
    public TestEntryData(String nameSpace, String name, int[] profileIds) {
    	this.nameSpace = nameSpace;
    	this.name = name;
    	this.profileIds = profileIds;
    }
    public TestEntryData(String nameSpace, String name, String value, int[] profileIds) {
    	this.nameSpace = nameSpace;
    	this.name = name;
    	this.valueCbor = CborTextString.create(value).toCborByteArray();
    	this.profileIds = profileIds;
    }
    public TestEntryData(String nameSpace, String name, byte[] value, int[] profileIds) {
    	this.nameSpace = nameSpace;
    	this.name = name;
    	this.valueCbor = CborByteString.create(value).toCborByteArray();
    	this.profileIds = profileIds;
    }
    public TestEntryData(String nameSpace, String name, boolean value, int[] profileIds) {
    	this.nameSpace = nameSpace;
    	this.name = name;
		this.valueCbor = (value ? CborSimple.TRUE : CborSimple.FALSE).toCborByteArray();
    	this.profileIds = profileIds;
    }
    public TestEntryData(String nameSpace, String name, int value, int[] profileIds) {
    	this.nameSpace = nameSpace;
    	this.name = name;
		this.valueCbor = CborInteger.create(value).toCborByteArray();
    	this.profileIds = profileIds;
    }
}
