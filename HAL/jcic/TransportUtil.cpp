/*
 **
 ** Copyright 2021, The Android Open Source Project
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
 
#include <vector>
#include <android-base/properties.h>
#include "Transport.h"
#include "TransportFactory.h"
#include "TransportUtil.h"

#define PROP_BUILD_QEMU              "ro.kernel.qemu"
#define PROP_BUILD_FINGERPRINT       "ro.build.fingerprint"
// Cuttlefish build fingerprint substring.
#define CUTTLEFISH_FINGERPRINT_SS    "aosp_cf_"

#define APDU_CLS 0x80
#define APDU_P1  0x40
#define APDU_P2  0x00
#define APDU_RESP_STATUS_OK 0x9000

#define INS_BEGIN_KM_CMD 0x00
#define INS_END_KM_PROVISION_CMD 0x20
#define INS_END_KM_CMD 0x7F
#define SW_KM_OPR 0UL
#define SB_KM_OPR 1UL
#define JAVACARD_KEYMASTER_VERSION 3

namespace se_transport {

static std::unique_ptr<se_transport::TransportFactory> pTransportFactory = nullptr;


static inline std::unique_ptr<se_transport::TransportFactory>& getTransportFactoryInstance() {
    bool isEmulator = false;
    if(pTransportFactory == nullptr) {
        // Check if the current build is for emulator or device.
        isEmulator = ::android::base::GetBoolProperty(PROP_BUILD_QEMU, false);
        if (!isEmulator) {
            std::string fingerprint = ::android::base::GetProperty(PROP_BUILD_FINGERPRINT, "");
            if (!fingerprint.empty()) {
                if (fingerprint.find(CUTTLEFISH_FINGERPRINT_SS, 0)) {
                    isEmulator = true;
                }
            }
        }
        pTransportFactory = std::unique_ptr<se_transport::TransportFactory>(new se_transport::TransportFactory(
                    isEmulator));
        pTransportFactory->openConnection();
    }
    return pTransportFactory;
}

int TransportUtil::constructApduMessage(Instruction& ins, std::vector<uint8_t>& inputData, std::vector<uint8_t>& apduOut) {
    apduOut.push_back(static_cast<uint8_t>(APDU_CLS)); //CLS
    apduOut.push_back(static_cast<uint8_t>(ins)); //INS
    apduOut.push_back(static_cast<uint8_t>(APDU_P1)); //P1
    apduOut.push_back(static_cast<uint8_t>(APDU_P2)); //P2

    if(USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le all set to 00.
        // Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        //Extended length 3 bytes, starts with 0x00
        apduOut.push_back(static_cast<uint8_t>(0x00));
        if (inputData.size() > 0) {
            apduOut.push_back(static_cast<uint8_t>(inputData.size() >> 8));
            apduOut.push_back(static_cast<uint8_t>(inputData.size() & 0xFF));
            //Data
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        }
        //Expected length of output.
        //Accepting complete length of output every time.
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));
    } else {
        return -1;
    }

    return 0;//success
}

uint16_t getStatus(std::vector<uint8_t>& inputData) {
    //Last two bytes are the status SW0SW1
    return (inputData.at(inputData.size()-2) << 8) | (inputData.at(inputData.size()-1));
}

int TransportUtil::sendData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response) {
    int ret = -1;
    std::vector<uint8_t> apdu;

    ret = constructApduMessage(ins, inData, apdu);
    if(ret != 0) return ret;

    if(!getTransportFactoryInstance()->sendData(apdu.data(), apdu.size(), response)) {
        return -1;
    }

    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU status.
    if((response.size() <= 2) || (getStatus(response) != APDU_RESP_STATUS_OK)) {
        return -1;
    }
    return 0;//success
}

}
