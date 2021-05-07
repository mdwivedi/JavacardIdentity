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

#include <vector>
#include "TransportFactory.h"

namespace se_transport {

static ITransportClient* mSocketTransport;
static ITransportClient* mOmapiTransport;

/**
 * TransportFactory class decides which transport mechanism to be used to send data to secure element. In case of
 * emulator the communication channel is socket and in case of device the communication channel is via OMAPI.
 */
ITransportClient* TransportFactory::getTransportClient(bool isEmulator) {
    if (!isEmulator) {
        if(!mOmapiTransport)
            mOmapiTransport = new OmapiTransport();
        return mOmapiTransport;
    } else {
        if(!mSocketTransport)
            mSocketTransport = new SocketTransport();
        return mSocketTransport;
    }
}

}
