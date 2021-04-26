package android.security.jcic.test;

public class TestEntryData {
    String nameSpace;
    String name;
    byte[] valueCbor;
    int[] profileIds;
    public TestEntryData(String nameSpace, String name, byte[] valueCbor, int[] profileIds) {
    	this.nameSpace = nameSpace;
    	this.name = name;
    	this.valueCbor = valueCbor;
    	this.profileIds = profileIds;
    }
}
