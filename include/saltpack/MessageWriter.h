/*
 * Copyright 2016-2017 Luca Zanconato
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

#ifndef SALTPACK_MESSAGEWRITER_H
#define SALTPACK_MESSAGEWRITER_H

#include <list>
#include "Base.h"

namespace saltpack {

    /**
     *  @brief The class used to encrypt or sign a message.
     *
     *  Use it in conjuction with ArmoredOutputStream to produce armored BaseX output.
     */
    class MessageWriter : public Base {

    public:
        /**
         * Creates a new MessageWriter instance to encrypt a message.
         *
         * @param os the destination output stream that will contain the encrypted data.
         * @param senderSecretkey the private key of the sender, generated by Utils::generateKeypair().
         * @param recipients the list of public keys of the recipients.
         * @param visibleRecipients if true, the public keys of the recipients will be visible in the encrypted message.
         *
         * @throws SaltpackException
         */
        MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, std::list<BYTE_ARRAY> recipients,
                      bool visibleRecipients);

        /**
         * Creates a new MessageWriter instance to encrypt a message.
         * The recipients public keys will be visible in the encrypted message.
         *
         * @param os the destination output stream that will contain the encrypted data.
         * @param senderSecretkey the private key of the sender, generated by Utils::generateKeypair().
         * @param recipients the list of public keys of the recipients.
         *
         * @throws SaltpackException
         */
        MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, std::list<BYTE_ARRAY> recipients);

        /**
         * Creates a new MessageWriter instance to encrypt a message remaining anonymous.
         *
         * @param os the destination output stream that will contain the encrypted data.
         * @param recipients the list of public keys of the recipients.
         * @param visibleRecipients if true, the public keys of the recipients will be visible in the encrypted message.
         *
         * @throws SaltpackException
         */
        MessageWriter(std::ostream &os, std::list<BYTE_ARRAY> recipients, bool visibleRecipients);

        /**
         * Creates a new MessageWriter instance to encrypt a message remaining anonymous.
         * The recipients public keys will be visible in the encrypted message.
         *
         * @param os the destination output stream that will contain the encrypted data.
         * @param recipients the list of public keys of the recipients.
         *
         * @throws SaltpackException
         */
        MessageWriter(std::ostream &os, std::list<BYTE_ARRAY> recipients);

        /**
         * Creates a new MessageWriter instance to sign a message.
         *
         * @param os the destination output stream that will contain the signed data.
         * @param senderSecretkey the private key of the sender, generated by Utils::generateSignKeypair().
         * @param detatchedSignature attached/detached signature flag.
         *
         * @throws SaltpackException
         */
        MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, bool detatchedSignature);

        // TODO: add docs
        MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, std::list<BYTE_ARRAY> recipientsPublickeys,
                      std::list<std::pair<BYTE_ARRAY, BYTE_ARRAY>> symmetricalKeys);

        /**
         * Desctructor. Securely deletes the allocated buffers using `sodium_memzero`.
         */
        virtual ~MessageWriter();

        /**
         * Adds a block to the current message.
         *
         * @param data the data for the block, maximum 1MB.
         * @param final the flag defining the last packet of the message.
         *
         * @throws SaltpackException
         */
        void addBlock(BYTE_ARRAY data, bool final);

    private:
        std::ostream &output;
        unsigned int packetIndex;
        BYTE_ARRAY payloadKey;
        BYTE_ARRAY headerHash;
        std::list<BYTE_ARRAY> macKeys;
        bool lastBlockAdded;

        BYTE_ARRAY secretKey;
        BYTE_ARRAY buffer;

        std::string generateEncryptionHeader(BYTE_ARRAY ephemeralSecretkey, BYTE_ARRAY ephemeralPublickey,
                                             BYTE_ARRAY senderPublickey, std::list<BYTE_ARRAY> recipientsPublickeys,
                                             bool visibleRecipients);

        std::string generateSignatureHeader(BYTE_ARRAY senderPublickey, bool detatchedSignature);

        std::string generateSigncryptionHeader(BYTE_ARRAY ephemeralSecretkey, BYTE_ARRAY ephemeralPublickey,
                                               BYTE_ARRAY senderPublickey, std::list<BYTE_ARRAY> recipientsPublickeys,
                                               std::list<std::pair<BYTE_ARRAY, BYTE_ARRAY>> symmetricalKeys);

        std::string encodeHeader(std::string header);

        BYTE_ARRAY generateAuthenticator(BYTE_ARRAY concat, BYTE_ARRAY recipientMacKey);

        std::string generatePayloadPacket(BYTE_ARRAY message, bool final);

        std::string generateSignaturePayloadPacket(BYTE_ARRAY message, bool final);

        std::string generateSigncryptionPayloadPacket(BYTE_ARRAY message, bool final);
    };
}

#endif //SALTPACK_MESSAGEWRITER_H
