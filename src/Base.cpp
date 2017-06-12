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

#include <sodium.h>
#include <saltpack/Utils.h>
#include "saltpack/Base.h"
#include "saltpack/SaltpackException.h"

namespace saltpack {

    Base::~Base() {

    }

    BYTE_ARRAY Base::generateMacKey(BYTE_ARRAY headerHashTrunc, BYTE_ARRAY publickey, BYTE_ARRAY secretkey) {

        // generate mac key for recipient
        BYTE_ARRAY macKeyLong(crypto_box_MACBYTES + ZEROES.size());
        if (crypto_box_easy(macKeyLong.data(), ZEROES.data(), ZEROES.size(),
                            headerHashTrunc.data(), publickey.data(), secretkey.data()) != 0)
            throw SaltpackException("Errors while generating mac key.");

        BYTE_ARRAY out(32);
        for (int i = 0; i < 32; i++)
            out[i] = macKeyLong[macKeyLong.size() - 32 + i];

        return out;
    }

    BYTE_ARRAY Base::generateMacKeyV2(BYTE_ARRAY headerHashTrunc, BYTE_ARRAY senderPublic, BYTE_ARRAY senderSecret,
                                      BYTE_ARRAY ephemeraPublic, BYTE_ARRAY ephemeralSecret, int recipientIndex) {

        // generate nonce
        BYTE_ARRAY nonce;
        nonce.reserve(headerHashTrunc.size() + 8);
        nonce.insert(nonce.end(), headerHashTrunc.begin(), headerHashTrunc.end());
        nonce.insert(nonce.end(), ZEROES.begin(), ZEROES.end() - 28);
        nonce.push_back((BYTE) ((recipientIndex >> 24) & 0xFF));
        nonce.push_back((BYTE) ((recipientIndex >> 16) & 0xFF));
        nonce.push_back((BYTE) ((recipientIndex >> 8) & 0XFF));
        nonce.push_back((BYTE) ((recipientIndex & 0XFF)));

        // generate sender box
        nonce[15] &= (BYTE) 254;
        BYTE_ARRAY boxSender(crypto_box_MACBYTES + ZEROES.size());
        if (crypto_box_easy(boxSender.data(), ZEROES.data(), ZEROES.size(),
                            nonce.data(), senderPublic.data(), senderSecret.data()) != 0)
            throw SaltpackException("Errors while generating mac key (sender box).");

        // generate ephemeral box
        nonce[15] |= (BYTE) 1;
        BYTE_ARRAY boxEphemeral(crypto_box_MACBYTES + ZEROES.size());
        if (crypto_box_easy(boxEphemeral.data(), ZEROES.data(), ZEROES.size(),
                            nonce.data(), ephemeraPublic.data(), ephemeralSecret.data()) != 0)
            throw SaltpackException("Errors while generating mac key (ephemeral box).");

        // concatenate boxes
        BYTE_ARRAY concat;
        concat.reserve(ZEROES.size() * 2);
        concat.insert(concat.end(), boxSender.begin() + crypto_box_MACBYTES, boxSender.end());
        concat.insert(concat.end(), boxEphemeral.begin() + crypto_box_MACBYTES, boxEphemeral.end());

        // hash of the concatenation
        BYTE_ARRAY concatHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(concatHash.data(), (const unsigned char *) concat.data(), concat.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        BYTE_ARRAY out(&concatHash[0], &concatHash[32]);

        return out;
    }

    BYTE_ARRAY Base::generatePayloadSecretboxNonce(int packetIndex) {

        BYTE_ARRAY payloadSecretboxNonce = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 'p', 'l', 'o',
                                            'a', 'd', 's', 'b', '\0', '\0', '\0', '\0'};
        payloadSecretboxNonce.push_back((BYTE) ((packetIndex >> 24) & 0xFF));
        payloadSecretboxNonce.push_back((BYTE) ((packetIndex >> 16) & 0xFF));
        payloadSecretboxNonce.push_back((BYTE) ((packetIndex >> 8) & 0XFF));
        payloadSecretboxNonce.push_back((BYTE) ((packetIndex & 0XFF)));

        return payloadSecretboxNonce;
    }

    BYTE_ARRAY Base::generateRecipientSecretboxNonce(int recipientIndex) {

        BYTE_ARRAY payloadSecretboxNonce = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 'r', 'e', 'c',
                                            'i', 'p', 's', 'b', '\0', '\0', '\0', '\0'};
        payloadSecretboxNonce.push_back((BYTE) ((recipientIndex >> 24) & 0xFF));
        payloadSecretboxNonce.push_back((BYTE) ((recipientIndex >> 16) & 0xFF));
        payloadSecretboxNonce.push_back((BYTE) ((recipientIndex >> 8) & 0XFF));
        payloadSecretboxNonce.push_back((BYTE) ((recipientIndex & 0XFF)));

        return payloadSecretboxNonce;
    }

    BYTE_ARRAY Base::generateValueForSignature(int packetIndex, BYTE_ARRAY headerHash, BYTE_ARRAY message) {

        // packet sequence
        BYTE_ARRAY packetSequence({0, 0, 0, 0});
        packetSequence.reserve(4);
        packetSequence.push_back((BYTE) ((packetIndex >> 24) & 0xFF));
        packetSequence.push_back((BYTE) ((packetIndex >> 16) & 0xFF));
        packetSequence.push_back((BYTE) ((packetIndex >> 8) & 0XFF));
        packetSequence.push_back((BYTE) ((packetIndex & 0XFF)));

        // concatenate header hash, packet sequence and payload chunk
        BYTE_ARRAY concat;
        concat.reserve(headerHash.size() + packetSequence.size() + message.size());
        concat.insert(concat.end(), headerHash.begin(), headerHash.end());
        concat.insert(concat.end(), packetSequence.begin(), packetSequence.end());
        concat.insert(concat.end(), message.begin(), message.end());

        // hash of the concatenation
        BYTE_ARRAY concatHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(concatHash.data(), (const unsigned char *) concat.data(), concat.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // concatenate SIGNATURE_ATTACHED_SIGNATURE and hash
        BYTE_ARRAY lConcat;
        lConcat.reserve(SIGNATURE_ATTACHED_SIGNATURE.size() + concatHash.size());
        lConcat.insert(lConcat.end(), SIGNATURE_ATTACHED_SIGNATURE.begin(), SIGNATURE_ATTACHED_SIGNATURE.end());
        lConcat.insert(lConcat.end(), concatHash.begin(), concatHash.end());

        return lConcat;
    }
}
