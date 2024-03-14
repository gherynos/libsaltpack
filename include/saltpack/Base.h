/*
 * Copyright 2016-2024 Luca Zanconato
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

#ifndef SALTPACK_BASE_H
#define SALTPACK_BASE_H

#include "types.h"

namespace saltpack {

    class Base {

    public:
        const BYTE_ARRAY SENDER_KEY_NONCE = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 's', 'e', 'n', 'd', 'e', 'r',
                                             '_', 'k', 'e', 'y', '_', 's', 'b', 'o', 'x'};
        const BYTE_ARRAY PAYLOAD_KEY_BOX_NONCE = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 'p', 'a', 'y', 'l', 'o',
                                                  'a', 'd', '_', 'k', 'e', 'y', '_', 'b', 'o', 'x'};
        const BYTE_ARRAY ZEROES = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0};
        const BYTE_ARRAY ZEROES_64 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        const BYTE_ARRAY SIGNATURE_ATTACHED_SIGNATURE = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', ' ', 'a', 't', 't',
                                                         'a', 'c', 'h', 'e', 'd', ' ', 's', 'i', 'g', 'n', 'a', 't',
                                                         'u', 'r', 'e', 0};
        const BYTE_ARRAY SIGNATURE_DETACHED_SIGNATURE = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', ' ', 'd', 'e', 't',
                                                         'a', 'c', 'h', 'e', 'd', ' ', 's', 'i', 'g', 'n', 'a', 't',
                                                         'u', 'r', 'e', 0};
        const BYTE_ARRAY DERIVED_SBOX_KEY = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 'd', 'e', 'r', 'i', 'v', 'e',
                                             'd', '_', 's', 'b', 'o', 'x', 'k', 'e', 'y'};
        const BYTE_ARRAY SIGNCRYPTION_BOX_KEY_IDENTIFIER = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', ' ', 's', 'i', 'g',
                                                            'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n', ' ', 'b', 'o',
                                                            'x', ' ', 'k', 'e', 'y', ' ', 'i', 'd', 'e', 'n', 't', 'i',
                                                            'f', 'i', 'e', 'r'};
        const BYTE_ARRAY SIGNCRYPTION_DERIVED_SYMMETRIC_KEY = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', ' ', 's', 'i',
                                                               'g', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n', ' ',
                                                               'd', 'e', 'r', 'i', 'v', 'e', 'd', ' ', 's', 'y', 'm',
                                                               'm', 'e', 't', 'r', 'i', 'c', ' ', 'k', 'e', 'y'};
        const BYTE_ARRAY ENCRYPTED_SIGNATURE = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', ' ', 'e', 'n', 'c', 'r', 'y',
                                                'p', 't', 'e', 'd', ' ', 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e'};

        virtual ~Base();

    protected:
        int mode = -1;

        static void appendConvertedValue(BYTE_ARRAY &out, unsigned long value);

        static BYTE_ARRAY generatePayloadSecretboxNonce(unsigned long packetIndex);

        static BYTE_ARRAY generateRecipientSecretboxNonce(unsigned long recipientIndex);

        BYTE_ARRAY generateMacKey(BYTE_ARRAY headerHashTrunc, BYTE_ARRAY publickey, BYTE_ARRAY secretkey);

        BYTE_ARRAY generateMacKeyV2(BYTE_ARRAY headerHashTrunc, BYTE_ARRAY senderPublic, BYTE_ARRAY senderSecret,
                                    BYTE_ARRAY ephemeraPublic, BYTE_ARRAY ephemeralSecret,
                                    unsigned long recipientIndex);

        BYTE_ARRAY generateValueForSignature(unsigned long packetIndex, BYTE_ARRAY headerHash, BYTE_ARRAY message,
                                             BYTE_ARRAY flag);

        BYTE_ARRAY deriveSharedKey(BYTE_ARRAY publickey, BYTE_ARRAY secretkey);

        BYTE_ARRAY deriveSharedKeySymmetric(BYTE_ARRAY publickey, BYTE_ARRAY secretkey);

        BYTE_ARRAY generateRecipientIdentifier(BYTE_ARRAY sharedSymmetricKey, BYTE_ARRAY payloadSecretboxNonce);

        BYTE_ARRAY generateSigncryptionPacketNonce(BYTE_ARRAY headerHash, unsigned long packetIndex, bool final);

        BYTE_ARRAY generateSignatureInput(BYTE_ARRAY packetNonce, BYTE_ARRAY headerHash, BYTE_ARRAY message, bool final);
    };
}

#endif //SALTPACK_BASE_H
