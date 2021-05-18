/*
**
** Copyright 2018, The Android Open Source Project
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
#ifndef ANDROID_HARDWARE_IDENTITY_JCIC_APPLETCONNECTION_H
#define ANDROID_HARDWARE_IDENTITY_JCIC_APPLETCONNECTION_H

#include "APDU.h"
#include "TransportClient.h"


namespace android::hardware::identity {


struct AppletConnection {
public:
    static constexpr uint8_t CLA_PROPRIETARY = 0x80;
    
    static constexpr size_t SW_WRONG_LENGTH = 0x6700;
    static constexpr size_t SW_SECURITY_CONDITIONS_NOT_SATISFIED = 0x6982;
    static constexpr size_t SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    static constexpr size_t SW_INCORRECT_PARAMETERS = 0x6A86;
    static constexpr size_t SW_INS_NOT_SUPPORTED = 0x6D00;
    static constexpr size_t SW_OK = 0x9000;

    static constexpr uint8_t INS_ICS_GET_VERSION =  0x50;
    static constexpr uint8_t INS_ICS_PING =  0x51;
    static constexpr uint8_t INS_ICS_CREATE_EPHEMERAL_KEY =  0x52;
    static constexpr uint8_t INS_ICS_TEST_CBOR =  0x53;
    static constexpr uint8_t INS_ICS_GET_HARDWARE_INFO = 0x54;

    /**
     * Credential provisioning instructions
     */
    static constexpr uint8_t INS_ICS_PROVISIONING_INIT =  0x10;
    static constexpr uint8_t INS_ICS_CREATE_CREDENTIAL_KEY =  0x11;
    static constexpr uint8_t INS_ICS_START_PERSONALIZATION =  0x12;
    static constexpr uint8_t INS_ICS_ADD_ACCESS_CONTROL_PROFILE =  0x13;
    static constexpr uint8_t INS_ICS_BEGIN_ADD_ENTRY =  0x14;
    static constexpr uint8_t INS_ICS_ADD_ENTRY_VALUE =  0x15;
    static constexpr uint8_t INS_ICS_FINISH_ADDING_ENTRIES =  0x16;
    static constexpr uint8_t INS_ICS_FINISH_GET_CREDENTIAL_DATA =  0x17;

    /**
     * Credential Presentation instructions
     */
    static constexpr uint8_t INS_ICS_PRESENTATION_INIT = 0x30;
    static constexpr uint8_t INS_ICS_CREATE_EPHEMERAL_KEY_PAIR = 0x31;
    static constexpr uint8_t INS_ICS_CREATE_AUTH_CHALLENGE = 0x32;
    static constexpr uint8_t INS_ICS_START_RETRIEVAL = 0x33;
    static constexpr uint8_t INS_ICS_SET_AUTH_TOKEN = 0x34;
    static constexpr uint8_t INS_ICS_PUSH_READER_CERT = 0x35;
    static constexpr uint8_t INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES = 0x36;
    static constexpr uint8_t INS_ICS_VALIDATE_REQUEST_MESSAGE = 0x37;
    static constexpr uint8_t INS_ICS_CAL_MAC_KEY = 0x38;
    static constexpr uint8_t INS_ICS_START_RETRIEVE_ENTRY_VALUE = 0x39;
    static constexpr uint8_t INS_ICS_RETRIEVE_ENTRY_VALUE = 0x3A;
    static constexpr uint8_t INS_ICS_FINISH_RETRIEVAL = 0x3B;
    static constexpr uint8_t INS_ICS_GENERATE_SIGNING_KEY_PAIR = 0x3C;
    static constexpr uint8_t INS_ICS_PROVE_OWNERSHIP  = 0x3D;
    static constexpr uint8_t INS_ICS_DELETE_CREDENTIAL = 0x3E;
    static constexpr uint8_t INS_ICS_UPDATE_CREDENTIAL = 0x3F;
    
    /**
     * Instruction bytes for standard ISO7816-4 commands 
     */
    static constexpr uint8_t INS_GET_RESPONSE =  0xC0;
    
    /**
     * Connects to the secure element HAL service. Returns true if successful, false otherwise.
     */
    bool connectToTransportClient();

    /**
     * Select the applet on the secure element and returns the select response message.
     */
    ResponseApdu openChannelToApplet();

    /**
     * If open, closes the open channel to the applet. Returns an error message if channel was not
     * open or the SE HAL service returned an error.
     */
    bool close();

    /**
     * Transmits the command APDU to the applet and response with the resulting Response APDU. If an
     * error occured during transmission, the ResponseApdu will be empty. If the applet returned an
     * error message, the ResponseApdu will contain a error message in ResponseApdu.status()
     */
    // const ResponseApdu<hidl_vec<uint8_t>> transmit(CommandApdu& command);
    const ResponseApdu transmit(CommandApdu& command);

    /**
     * Checks if a chennel to the applet is open.
     */
    bool isChannelOpen();

    /**
     * Return the maximum chunk size of the applet
     */
    uint16_t chunkSize() { return mHalChunkSize; }
private:
    se_transport::ITransportClient* mTransportClient;

    uint16_t mApduMaxBufferSize = 255;
    uint16_t mAppletChunkSize = 0;
    uint16_t mHalChunkSize = 0;

    int8_t mOpenChannel = -1;
};

}  // namespace aidl::android::hardware::identity
#endif  // ANDROID_HARDWARE_IDENTITY_JCIC_APPLETCONNECTION_H

