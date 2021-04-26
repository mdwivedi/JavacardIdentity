package android.security.jcic.test;

public class TestProfile {
    int id;
    byte[] readerCertificate;
    boolean userAuthenticationRequired;
    int timeoutMillis;
    int secureUserId;
    public TestProfile(int id, byte[] readerCertificate, boolean userAuthenticationRequired, int timeoutMillis) {
    	this.id = id;
    	this.readerCertificate = readerCertificate;
    	this.userAuthenticationRequired = userAuthenticationRequired;
    	this.timeoutMillis = timeoutMillis;
    	this.secureUserId = userAuthenticationRequired ? 66 : 0;
    }
}
