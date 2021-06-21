package android.security.jcic;

class ICConstants {
    public static final byte BYTE_SIZE = 1;
    public static final byte SHORT_SIZE = 2;
    public static final byte INT_SIZE = 4;
    public static final byte LONG_SIZE = 8;


    public static final short MAX_NUM_ACCESS_CONTROL_PROFILE_IDS = 32;
    public static final short MAX_NUM_NAMESPACES = 32;

    public static final byte STATUS_NUM_ENTRY_COUNTS = 0;
    public static final byte STATUS_CURRENT_NAMESPACE = 1;
    public static final byte STATUS_CURRENT_NAMESPACE_NUM_PROCESSED = 2;
    public static final byte STATUS_WORDS = 3;

    public static final byte COSE_SIGN_ALG = (byte)0xF9; //-7

    //Signature1
    public static final byte[] STR_SIGNATURE1 = new byte[] {(byte)0x53, (byte)0x69, (byte)0x67, (byte)0x6E, (byte)0x61,
            (byte)0x74, (byte)0x75, (byte)0x72, (byte)0x65, (byte)0x31};
    //ProofOfProvisioning
    public static final byte[] STR_PROOF_OF_PROVISIONING = new byte[] {(byte)0x50, (byte)0x72, (byte)0x6f, (byte)0x6f,
            (byte)0x66, (byte)0x4f, (byte)0x66, (byte)0x50, (byte)0x72,
            (byte)0x6f, (byte)0x76, (byte)0x69, (byte)0x73, (byte)0x69,
            (byte)0x6f, (byte)0x6e, (byte)0x69, (byte)0x6e, (byte)0x67};
    //id
    public static final byte[] STR_ID = new byte[] {(byte)0x69, (byte)0x64};
    //readerCertificate
    public static final byte[] STR_READER_CERTIFICATE = new byte[] {(byte)0x72, (byte)0x65, (byte)0x61, (byte)0x64,
            (byte)0x65, (byte)0x72, (byte)0x43, (byte)0x65, (byte)0x72,
            (byte)0x74, (byte)0x69, (byte)0x66, (byte)0x69, (byte)0x63,
            (byte)0x61, (byte)0x74, (byte)0x65};
    //userAuthenticationRequired
    public static final byte[] STR_USER_AUTH_REQUIRED = new byte[] {(byte)0x75, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x41,
            (byte)0x75, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x6e, (byte)0x74,
            (byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f,
            (byte)0x6e, (byte)0x52, (byte)0x65, (byte)0x71, (byte)0x75, (byte)0x69,
            (byte)0x72, (byte)0x65, (byte)0x64};
    //timeoutMillis
    public static final byte[] STR_TIMEOUT_MILIS = new byte[] {(byte)0x74, (byte)0x69, (byte)0x6d, (byte)0x65, (byte)0x6f,
            (byte)0x75, (byte)0x74, (byte)0x4d, (byte)0x69, (byte)0x6c, (byte)0x6c,
            (byte)0x69, (byte)0x73};
    //secureUserId
    public static final byte[] STR_SECURE_USER_ID = new byte[] {(byte)0x73, (byte)0x65, (byte)0x63, (byte)0x75, (byte)0x72,
            (byte)0x65, (byte)0x55, (byte)0x73, (byte)0x65, (byte)0x72, (byte)0x49,
            (byte)0x64};
    //name
    public static final byte[] STR_NAME = {(byte) 0x6e, (byte) 0x61, (byte) 0x6d, (byte) 0x65};
    //value
    public static final byte[] STR_VALUE = {(byte) 0x76, (byte) 0x61, (byte) 0x6c, (byte) 0x75, (byte) 0x65};
    //Namespace
    public static final byte[] STR_NAME_SPACE = {(byte) 0x4e, (byte) 0x61, (byte) 0x6d, (byte) 0x65, (byte) 0x73, (byte) 0x70, (byte) 0x61, (byte) 0x63, (byte) 0x65};
    //AccessControlProfileIds
    public static final byte[] STR_ACCESS_CONTROL_PROFILE_IDS = {(byte) 0x41, (byte) 0x63, (byte) 0x63, (byte) 0x65,
            (byte) 0x73, (byte) 0x73, (byte) 0x43, (byte) 0x6f, (byte) 0x6e,
            (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6c, (byte) 0x50,
            (byte) 0x72, (byte) 0x6f, (byte) 0x66, (byte) 0x69, (byte) 0x6c,
            (byte) 0x65, (byte) 0x49, (byte) 0x64, (byte) 0x73};
    //accessControlProfiles
    public static final byte[] STR_ACCESS_CONTROL_PROFILES = {(byte) 0x61, (byte) 0x63, (byte) 0x63, (byte) 0x65,
            (byte) 0x73, (byte) 0x73, (byte) 0x43, (byte) 0x6f, (byte) 0x6e,
            (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6c, (byte) 0x50,
            (byte) 0x72, (byte) 0x6f, (byte) 0x66, (byte) 0x69, (byte) 0x6c,
            (byte) 0x65, (byte) 0x73};

    public static final byte[] COSE_ENCODED_PROTECTED_HEADERS_ECDSA = {(byte) 0xa1, (byte)0x01, (byte)0x26};
    public static final byte[] COSE_ENCODED_PROTECTED_HEADERS_HMAC = {(byte) 0xa1, (byte)0x01, (byte)0x05};

    //ProofOfBinding
    public static final byte[] STR_PROOF_OF_BINDING = {(byte) 0x50, (byte) 0x72, (byte) 0x6f, (byte) 0x6f, (byte) 0x66, (byte) 0x4f, (byte) 0x66, (byte) 0x42, (byte) 0x69, (byte) 0x6e, (byte) 0x64, (byte) 0x69, (byte) 0x6e, (byte) 0x67};

    //ReaderAuthentication
    public static final byte[] STR_READER_AUTHENTICATION = {(byte) 0x52, (byte) 0x65, (byte) 0x61, (byte) 0x64, (byte) 0x65, (byte) 0x72,
                                        (byte) 0x41, (byte) 0x75, (byte) 0x74, (byte) 0x68, (byte) 0x65, (byte) 0x6e,
                                        (byte) 0x74, (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x69,
                                        (byte) 0x6f, (byte) 0x6e};

    public static final byte CBOR_SEMANTIC_TAG_ENCODED_CBOR = (byte)24;

    public static final byte[] EMAC_KEY_INFO = {'E', 'M', 'a', 'c', 'K', 'e', 'y'};
    public static final byte[] MAC0 = {'M', 'A', 'C', '0'};
    //DeviceAuthentication
    public static final byte[] STR_DEVICE_AUTHENTICATION = {'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n'};

    //ProofOfOwnership
    public static final byte[] STR_PROOF_OF_OWNERSHIP = {'P', 'r', 'o', 'o', 'f', 'O', 'f', 'O', 'w', 'n', 'e', 'r', 's', 'h', 'i', 'p'};

    //ProofOfDeletion
    public static final byte[] STR_PROOF_OF_DELETION = {'P', 'r', 'o', 'o', 'f', 'O', 'f', 'D', 'e', 'l', 'e', 't', 'i', 'o', 'n'};

    public static final byte[] X509_CERT_BASE = {(byte)0x30, (byte)0x82, (byte)0x01, (byte)0x40, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x3C, (byte)0xA0, (byte)0x03, (byte)0x02, (byte)0x01, (byte)0x02, (byte)0x02, (byte)0x01, (byte)0x01,
            (byte)0x30, (byte)0x0A, (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x30, (byte)0x2A, (byte)0x31, (byte)0x28,
            (byte)0x30, (byte)0x26, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0C, (byte)0x1F, (byte)0x41, (byte)0x6E, (byte)0x64, (byte)0x72, (byte)0x6F, (byte)0x69, (byte)0x64,
            (byte)0x20, (byte)0x49, (byte)0x64, (byte)0x65, (byte)0x6E, (byte)0x74, (byte)0x69, (byte)0x74, (byte)0x79, (byte)0x20, (byte)0x43, (byte)0x72, (byte)0x65, (byte)0x64, (byte)0x65, (byte)0x6E,
            (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x6C, (byte)0x20, (byte)0x4B, (byte)0x65, (byte)0x79, (byte)0x30, (byte)0x1E, (byte)0x17, (byte)0x0D, (byte)0x32, (byte)0x31, (byte)0x30, (byte)0x35,
            (byte)0x31, (byte)0x31, (byte)0x30, (byte)0x38, (byte)0x33, (byte)0x37, (byte)0x34, (byte)0x39, (byte)0x5A, (byte)0x17, (byte)0x0D, (byte)0x32, (byte)0x32, (byte)0x30, (byte)0x35, (byte)0x31,
            (byte)0x31, (byte)0x30, (byte)0x38, (byte)0x33, (byte)0x37, (byte)0x34, (byte)0x39, (byte)0x5A, (byte)0x30, (byte)0x39, (byte)0x31, (byte)0x37, (byte)0x30, (byte)0x35, (byte)0x06, (byte)0x03,
            (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0C, (byte)0x2E, (byte)0x41, (byte)0x6E, (byte)0x64, (byte)0x72, (byte)0x6F, (byte)0x69, (byte)0x64, (byte)0x20, (byte)0x49, (byte)0x64, (byte)0x65,
            (byte)0x6E, (byte)0x74, (byte)0x69, (byte)0x74, (byte)0x79, (byte)0x20, (byte)0x43, (byte)0x72, (byte)0x65, (byte)0x64, (byte)0x65, (byte)0x6E, (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x6C,
            (byte)0x20, (byte)0x41, (byte)0x75, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x6E, (byte)0x74, (byte)0x69, (byte)0x63, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6F, (byte)0x6E, (byte)0x20,
            (byte)0x4B, (byte)0x65, (byte)0x79, (byte)0x30, (byte)0x59, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01,
            (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x03, (byte)0x42, (byte)0x00};
    public static final byte[] X509_DER_POB = {(byte)0xA3, (byte)0x44, (byte)0x30, (byte)0x42, (byte)0x30, (byte)0x40, (byte)0x06, (byte)0x0A, (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0xD6,
            (byte)0x79, (byte)0x02, (byte)0x01, (byte)0x1A, (byte)0x04, (byte)0x32 };
    public static final byte[] X509_DER_SIGNATURE = {(byte)0x30, (byte)0x0A, (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x03, (byte)0x47, (byte)0x00};
    public static final byte[] DER_PUB_KEY_OID = {(byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02,
                          (byte)0x01};
    public static final byte[] DER_EC_KEY_CURVE_OID = {(byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
            (byte)0x03, (byte)0x01, (byte)0x07};

    public static final byte X509_CERT_POS_TOTAL_LEN = (short)2;

    //byte X509_CERT_POS_SERIAL_NUM = (short)14;

    public static final byte X509_CERT_POS_VALID_AFTER = (short)76;

    public static final byte X509_CERT_POS_VALID_BEFORE = (short)91;

    public static final short X509_CERT_POS_PUB_KEY = (short)259;

    public static final short X509_CERT_POS_POB = (short)183;
}
