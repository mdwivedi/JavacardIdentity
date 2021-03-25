/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
#ifndef __SE_TRANSPORT_UTIL__
#define __SE_TRANSPORT_UTIL__

namespace se_transport {

enum class Instruction {
    INS_ICS_GET_VERSION =  0x50,
    INS_ICS_PING =  0x51,
    INS_ICS_CREATE_EPHEMERAL_KEY =  0x52,
    INS_ICS_TEST_CBOR =  0x53,

    /**
     * Credential provisioning instructions
     */
    INS_ICS_CREATE_CREDENTIAL =  0x10,
    INS_ICS_GET_ATTESTATION_CERT =  0x11,
    INS_ICS_PERSONALIZE_ACCESS_CONTROL =  0x12,
    INS_ICS_PERSONALIZE_NAMESPACE =  0x13,
    INS_ICS_PERSONALIZE_ATTRIBUTE =  0x14,
    INS_ICS_SIGN_PERSONALIZED_DATA =  0x15,

    /**
     * Credential Management instructions
     */
    INS_ICS_LOAD_CREDENTIAL_BLOB =  0x30,
    INS_ICS_AUTHENTICATE =  0x31,
    INS_ICS_LOAD_ACCESS_CONTROL_PROFILE =  0x32,
    INS_ICS_GET_NAMESPACE =  0x3A,
    INS_ICS_GET_ENTRY =  0x3B,
    INS_ICS_CREATE_SIGNATURE =  0x3C,
    INS_ICS_CREATE_SIGNING_KEY=  0x40,
    
    /**
     * Instruction bytes for standard ISO7816-4 commands 
     */
    INS_GET_RESPONSE =  0xC0,
};


class TransportUtil {
public:
    TransportUtil(){}
    ~TransportUtil(){}
    int constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut);
    int sendData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response);
};

}
#endif /* __SE_TRANSPORT__ */
