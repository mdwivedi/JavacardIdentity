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

#define LOG_TAG "android.hardware.identity-service.jcic"
#include <android-base/logging.h>
#include <android-base/properties.h>

#include "AppletConnection.h"
#include "APDU.h"
#include "TransportFactory.h"

#include <cmath>
#include <functional>

#define PROP_BUILD_QEMU              "ro.kernel.qemu"
#define PROP_BUILD_FINGERPRINT       "ro.build.fingerprint"
// Cuttlefish build fingerprint substring.
#define CUTTLEFISH_FINGERPRINT_SS    "aosp_cf_"

using se_transport::TransportFactory;
namespace android::hardware::identity {

const std::vector<uint8_t> kAndroidIdentityCredentialAID = {
        0xA0, 0x00, 0x00, 0x04, 0x76, 0x02, 0x0C, 0x01, 0x01, 0x01};

const uint8_t kINSGetRespone = 0xc0;
const uint8_t kMaxCBORHeader = 5;
//const uint8_t kDefMaxApduHeader = 6;
//const uint8_t kDefaultApduSize = 0xFF;
// TODO: investigate why 3 additional bytes overhead are required for pixel 2
//const uint8_t kExtendedMaxApduHeader = 13; 

bool AppletConnection::connectToTransportClient() {
    if (mTransportClient != nullptr) {
        LOG(DEBUG) << "Already connected";
        return true;
    }
    bool isEmulator = false;
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

    mTransportClient = TransportFactory::getTransportClient(isEmulator);

    if (mTransportClient != nullptr) {
        
        mTransportClient->openConnection();
        return true;
    }
    return false;
}

ResponseApdu AppletConnection::openChannelToApplet() {
    if (isChannelOpen()) {
        close();
    }
    if (mTransportClient == nullptr) {  // Not connected to SE service
        return ResponseApdu({});
    }

    std::vector<uint8_t> resp;
    /*mTransportClient->openLogicalChannel(
        kAndroidIdentityCredentialAID, 00,
        [&](LogicalChannelResponse selectResponse, SecureElementStatus status) {
            if (status == SecureElementStatus::SUCCESS) {
                resp = selectResponse.selectResponse;
                // TODO: verify that an APDU buffer >255 represent support for extended length APDU 
                // APDU buffer size is encoded in select response
                mApduMaxBufferSize = (*resp.begin() << 8) + *(resp.begin() + 1);
                mApduMaxBufferSize -= mApduMaxBufferSize <= (kDefaultApduSize + kDefMaxApduHeader)
                                              ? kDefMaxApduHeader
                                              : kExtendedMaxApduHeader;

                // Chunck size is encoded in select response
                mAppletChunkSize = (*(resp.begin()+2) << 8) + *(resp.begin() + 3);

                // Actual maximum data chunk size needs to take cbor header in account
                mHalChunkSize = mAppletChunkSize - kMaxCBORHeader;

                mOpenChannel = selectResponse.channelNumber;
            }
        });*/
    mApduMaxBufferSize = 230;
    mAppletChunkSize = 1024;
    mHalChunkSize = mAppletChunkSize - kMaxCBORHeader;
    mOpenChannel = 0x00;
    resp.push_back(0x90);
    resp.push_back(0x00);
    return ResponseApdu(resp);
}

const ResponseApdu AppletConnection::transmit(CommandApdu& command) {
    if (!isChannelOpen() || mTransportClient == nullptr) {
        return ResponseApdu(std::vector<uint8_t>{0});
    }

    bool getResponseEmpty = false;
    std::vector<uint8_t> fullResponse;
    uint16_t nrOfAPDUchains = 1;
 
    // Configure the logical channel
    *command.begin() |= mOpenChannel;

    /*if (command.dataSize() > mAppletChunkSize) {
        LOG(ERROR) << "Data too big (" << command.dataSize() << "/" << mAppletChunkSize << "), abort";
        return ResponseApdu({});
    } else*/ if (command.size() > mApduMaxBufferSize) {
        // Too big for APDU buffer, perform APDU chaining
        nrOfAPDUchains = std::ceil(static_cast<float>(command.dataSize()) / mApduMaxBufferSize);
        LOG(DEBUG) << "Too big for APDU buffer. Sending " << nrOfAPDUchains << " chains";
    }

    std::vector<uint8_t> cmdVec = command.vector();
    
    // Send data (potentially in multiple chains)
    for (uint8_t i = 0; i < nrOfAPDUchains; i++) {
        size_t apduSize = 0;
        if (((i + 1) * mApduMaxBufferSize) <= command.dataSize()) {
            apduSize = mApduMaxBufferSize;
        } else {
            apduSize = command.dataSize() - i * mApduMaxBufferSize;
        }

        CommandApdu subCommand(cmdVec[0], cmdVec[1], cmdVec[2], cmdVec[3], apduSize, 0);

        auto first = command.dataBegin() + (i * mApduMaxBufferSize);
        auto last = first + apduSize;
        std::copy(first, last, subCommand.dataBegin());

        if (i != nrOfAPDUchains - 1) {
            *subCommand.begin() |= 0x10; // APDU chain
        }

        std::vector<uint8_t> responseData;
        mTransportClient->transmit(subCommand.vector(), responseData);
        LOG(DEBUG) << "Data received: " << responseData.size();
        fullResponse = responseData;
    
        if (fullResponse.size() < 2) {
            return ResponseApdu({});
        }
        // If chain did not end, response should be 0x900
        if ((i + 1) < nrOfAPDUchains && (*(fullResponse.end() - 2) != 0x90) &&
            (*(fullResponse.end() - 1)) != 0x00) {
            return ResponseApdu(fullResponse);
        }
    }

    // Check if more data is available 
    while (fullResponse.size() >= 2 && (*(fullResponse.end() - 2) == 0x61) && !getResponseEmpty) {
        uint8_t le = *(fullResponse.end() - 1);
        CommandApdu getResponse =
                CommandApdu(mOpenChannel, kINSGetRespone, 0, 0, 0, le == 0 ? mApduMaxBufferSize : le);

        std::vector<uint8_t> responseData;
        mTransportClient->transmit(getResponse.vector(), responseData);
        if (responseData.size() < 2) {
            *(fullResponse.end() - 2) = 0x67;  // Wrong length
            *(fullResponse.end() - 1) = 0x00;
        } else {
            // Copy additional data to response buffer
            fullResponse.resize(fullResponse.size() + responseData.size() - 2);

            std::copy(responseData.begin(), responseData.end(),
                      fullResponse.end() - responseData.size());

            if (responseData.size() == 2){
                getResponseEmpty = true;
            }
        }
    }

    return ResponseApdu(fullResponse);
}

bool AppletConnection::close() {
    if (!isChannelOpen() || mTransportClient == nullptr) {
        return false;
    }

    if (!mTransportClient->closeConnection()) {
        return false;
    }
    LOG(DEBUG) << "Channel closed";
    mOpenChannel = -1;
    return true;
}

bool AppletConnection::isChannelOpen() {
    return mOpenChannel >= 0;
}

}  // namespace android::hardware::identity

