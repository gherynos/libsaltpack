/*
 * Copyright 2016 Luca Zanconato
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SALTPACK_DECRYPTOR_H
#define SALTPACK_DECRYPTOR_H

#include <msgpack.hpp>
#include "Base.h"
#include "PayloadPacket.h"
#include "SignaturePayloadPacket.h"

namespace saltpack {

    class MessageReader : public Base {

    public:
        MessageReader(std::istream &is, BYTE_ARRAY recipientSecretkey);

        MessageReader(std::istream &is);

        MessageReader(std::istream &is, std::istream &messageStream);

        virtual ~MessageReader();

        BYTE_ARRAY getBlock();

        bool hasMoreBlocks();

    private:
        BYTE_ARRAY headerHash;
        BYTE_ARRAY payloadKey;
        BYTE_ARRAY macKey;
        int recipientIndex;
        unsigned int packetIndex;
        std::istream &input;
        msgpack::unpacker unpacker;
        bool lastBlockFound;

        BYTE_ARRAY publicKey;

        void processEncryptionHeader(std::vector<char> headerBin, BYTE_ARRAY recipientSecretkey);

        void processSignatureHeader(std::vector<char> headerBin);

        BYTE_ARRAY decryptPacket(PayloadPacket packet);

        BYTE_ARRAY verifyPacket(SignaturePayloadPacket packet);
    };
}

#endif //SALTPACK_DECRYPTOR_H
