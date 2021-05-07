package android.security.jcic;

interface ICConstants {
    byte BYTE_SIZE = 1;
    byte SHORT_SIZE = 2;
    byte INT_SIZE = 4;
    byte LONG_SIZE = 8;


    short MAX_NUM_ACCESS_CONTROL_PROFILE_IDS = 32;
    short MAX_NUM_NAMESPACES = 32;

    byte STATUS_NUM_ENTRY_COUNTS = 0;
    byte STATUS_CURRENT_NAMESPACE = 1;
    byte STATUS_CURRENT_NAMESPACE_NUM_PROCESSED = 2;
    byte STATUS_WORDS = 3;

    //Signature1
    byte[] STR_SIGNATURE1 = new byte[] {(byte)0x53, (byte)0x69, (byte)0x67, (byte)0x6E, (byte)0x61,
            (byte)0x74, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x31};
    //ProofOfProvisioning
    byte[] STR_PROOF_OF_PROVISIONING = new byte[] {(byte)0x50, (byte)0x72, (byte)0x6f, (byte)0x6f,
            (byte)0x66, (byte)0x4f, (byte)0x66, (byte)0x50, (byte)0x72,
            (byte)0x6f, (byte)0x76, (byte)0x69, (byte)0x73, (byte)0x69,
            (byte)0x6f, (byte)0x6e, (byte)0x69, (byte)0x6e, (byte)0x67};
    //id
    byte[] STR_ID = new byte[] {(byte)0x69, (byte)0x64};
    //readerCertificate
    byte[] STR_READER_CERTIFICATE = new byte[] {(byte)0x72, (byte)0x65, (byte)0x61, (byte)0x64,
            (byte)0x65, (byte)0x72, (byte)0x43, (byte)0x65, (byte)0x72,
            (byte)0x74, (byte)0x69, (byte)0x66, (byte)0x69, (byte)0x63,
            (byte)0x61, (byte)0x74, (byte)0x65};
    //userAuthenticationRequired
    byte[] STR_USER_AUTH_REQUIRED = new byte[] {(byte)0x75, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x41,
            (byte)0x75, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x6e, (byte)0x74,
            (byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f,
            (byte)0x6e, (byte)0x52, (byte)0x65, (byte)0x71, (byte)0x75, (byte)0x69,
            (byte)0x72, (byte)0x65, (byte)0x64};
    //timeoutMillis
    byte[] STR_TIMEOUT_MILIS = new byte[] {(byte)0x74, (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x6f,
            (byte)0x75, (byte)0x74, (byte)0x4d, (byte)0x69, (byte)0x6c, (byte)0x6c,
            (byte)0x69, (byte)0x73};
    //secureUserId
    byte[] STR_SECURE_USER_ID = new byte[] {(byte)0x73, (byte)0x65, (byte)0x63, (byte)0x75, (byte)0x72,
            (byte)0x65, (byte)0x55, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x49,
            (byte)0x64};
    //name
    byte[] STR_NAME = {(byte) 0x6e, (byte) 0x61, (byte) 0x6d, (byte) 0x65};
    //value
    byte[] STR_VALUE = {(byte) 0x76, (byte) 0x61, (byte) 0x6c, (byte) 0x75, (byte) 0x65};
    //Namespace
    byte[] STR_NAME_SPACE = {(byte) 0x4e, (byte) 0x61, (byte) 0x6d, (byte) 0x65, (byte) 0x73, (byte) 0x70, (byte) 0x61, (byte) 0x63, (byte) 0x65};
    //AccessControlProfileIds
    byte[] STR_ACCESS_CONTROL_PROFILE_IDS = {(byte) 0x41, (byte) 0x63, (byte) 0x63, (byte) 0x65,
            (byte) 0x73, (byte) 0x73, (byte) 0x43, (byte) 0x6f, (byte) 0x6e,
            (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6c, (byte) 0x50,
            (byte) 0x72, (byte) 0x6f, (byte) 0x66, (byte) 0x69, (byte) 0x6c,
            (byte) 0x65, (byte) 0x49, (byte) 0x64, (byte) 0x73};
    //accessControlProfiles
    byte[] STR_ACCESS_CONTROL_PROFILES = {(byte) 0x61, (byte) 0x63, (byte) 0x63, (byte) 0x65,
            (byte) 0x73, (byte) 0x73, (byte) 0x43, (byte) 0x6f, (byte) 0x6e,
            (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6c, (byte) 0x50,
            (byte) 0x72, (byte) 0x6f, (byte) 0x66, (byte) 0x69, (byte) 0x6c,
            (byte) 0x65, (byte) 0x73};

    byte[] COSE_ENCODED_PROTECTED_HEADERS = {(byte) 0xa1, (byte)0x01, (byte)0x26};

    //ProofOfBinding
    byte[] STR_PROOF_OF_BINDING = {(byte) 0x50, (byte) 0x72, (byte) 0x6f, (byte) 0x6f, (byte) 0x66, (byte) 0x4f, (byte) 0x66, (byte) 0x42, (byte) 0x69, (byte) 0x6e, (byte) 0x64, (byte) 0x69, (byte) 0x6e, (byte) 0x67};

}
