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

#ifndef SALTPACK_ENCRYPTOR_H
#define SALTPACK_ENCRYPTOR_H

#include <list>
#include "Base.h"

namespace saltpack {

    class MessageWriter : public Base {

    public:
        MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, std::list<BYTE_ARRAY> recipients,
                      bool visibleRecipients);

        MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, bool detatchedSignature);

        virtual ~MessageWriter();

        void addBlock(BYTE_ARRAY data);

        void finalise();

    private:
        std::ostream &output;
        unsigned int packetIndex;
        BYTE_ARRAY payloadKey;
        BYTE_ARRAY headerHash;
        std::list<BYTE_ARRAY> macKeys;

        BYTE_ARRAY secretKey;
        BYTE_ARRAY buffer;

        std::string generateEncryptionHeader(BYTE_ARRAY payloadKey, BYTE_ARRAY senderPublickey,
                                                                std::list<BYTE_ARRAY> recipientsPublickeys,
                                                                bool visibleRecipients);

        std::string generateSignatureHeader(BYTE_ARRAY senderPublickey, bool detatchedSignature);

        std::string encodeHeader(std::string header);

        BYTE_ARRAY generateAuthenticator(BYTE_ARRAY concat, BYTE_ARRAY recipientMacKey);

        std::string generatePayloadPacket(BYTE_ARRAY message);

        std::string generateSignaturePayloadPacket(BYTE_ARRAY message);
    };
}

#endif //SALTPACK_ENCRYPTOR_H
