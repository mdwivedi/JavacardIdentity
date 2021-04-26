package android.security.jcic.test;

public class PersonalizationData {
	String docType;
	int accessControlProfileCounts;
	int[] entryCounts;
	int expectedProofOfProvisioingSize;
	
	public PersonalizationData(String docType, int accessControlProfileCounts, int[] entryCounts, int expectedProofOfProvisioingSize) {
		this.docType = docType;
		this.accessControlProfileCounts = accessControlProfileCounts;
		this.entryCounts = entryCounts;
		this.expectedProofOfProvisioingSize = expectedProofOfProvisioingSize;
	}
}
