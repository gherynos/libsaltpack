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

    /**
     *  @brief The class used to decrypt or verify a message.
     *
     *  Use it in conjuction with ArmoredInputStream to process armored BaseX input.
     */
    class MessageReader : public Base {

    public:
        /**
         * Creates a new MessageReader instance to decrypt a message.
         *
         * @param is the source input stream containing the encrypted message.
         * @param recipientSecretkey the private key of the sender.
         *
         * @throws SaltpackException
         */
        MessageReader(std::istream &is, BYTE_ARRAY recipientSecretkey);

        /**
         * Creates a new MessageReader instance to verify a signed message.
         *
         * @param is the source input stream containing the message with its signature attached.
         *
         * @throws SaltpackException
         */
        MessageReader(std::istream &is);

        /**
         * Creates a new MessageReader instance to verify a signed message.
         *
         * @param is the source input stream containing the detached signature.
         * @param messageStream the input stream containing the message to verify.
         *
         * @throws SaltpackException if the signature verification fails.
         */
        MessageReader(std::istream &is, std::istream &messageStream);

        /**
         * Desctructor. Securely deletes the allocated buffers using `sodium_memzero`.
         */
        virtual ~MessageReader();

        /**
         * Returns the next block of the decrypted/verified message.
         *
         * @throws SaltpackException if the block cannot be decrypted or its signature is not valid.
         *
         * @return the decrypted/verified data.
         */
        BYTE_ARRAY getBlock();

        /**
         * Helper method to process all the blocks.
         *
         * @throws SaltpackException
         *
         * @return true when there are more blocks to read, false otherwise.
         */
        bool hasMoreBlocks();

        /**
         * Returns the public keys of the recipients if they're visible (see flag `visibleRecipients` in MessageWriter).
         *
         * @throws SaltpackException
         *
         * @return the recipients if they're visible, an empty list otherwise.
         */
        std::list<BYTE_ARRAY> getRecipients();

        /**
         * Returns the public key of the sender.
         *
         * @return the sender's public key.
         */
        BYTE_ARRAY getSender();

        /**
         * Sender's anonimity status (see MessageWriter::MessageWriter(std::ostream &, std::list<BYTE_ARRAY>)).
         *
         * @throws SaltpackException
         *
         * @return true if the sender of the message is intentionally anonymous, false otherwise.
         */
        bool isIntentionallyAnonymous();

    private:
        BYTE_ARRAY headerHash;
        BYTE_ARRAY payloadKey;
        BYTE_ARRAY macKey;
        int recipientIndex;
        std::list<BYTE_ARRAY> recipients;
        unsigned int packetIndex;
        std::istream &input;
        msgpack::unpacker unpacker;
        bool lastBlockFound;
        bool intentionallyAnonymous;

        BYTE_ARRAY senderPublickey;

        void processEncryptionHeader(std::vector<char> headerBin, BYTE_ARRAY recipientSecretkey);

        void processSignatureHeader(std::vector<char> headerBin);

        BYTE_ARRAY decryptPacket(PayloadPacket packet);

        BYTE_ARRAY verifyPacket(SignaturePayloadPacket packet);
    };
}

#endif //SALTPACK_DECRYPTOR_H
