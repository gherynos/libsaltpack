/*
 * Copyright 2016-2020 Luca Zanconato
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

    Base::~Base() = default;

    void Base::appendConvertedValue(BYTE_ARRAY &out, unsigned long value) {

        out.push_back((BYTE) (value >> 24u & 0xFFu));
        out.push_back((BYTE) (value >> 16u & 0xFFu));
        out.push_back((BYTE) (value >> 8u & 0XFFu));
        out.push_back((BYTE) (value & 0XFFu));
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
                                      BYTE_ARRAY ephemeraPublic, BYTE_ARRAY ephemeralSecret,
                                      unsigned long recipientIndex) {

        // generate nonce
        BYTE_ARRAY nonce;
        nonce.reserve(headerHashTrunc.size() + 8);
        nonce.insert(nonce.end(), headerHashTrunc.begin(), headerHashTrunc.end());
        nonce.insert(nonce.end(), ZEROES.begin(), ZEROES.end() - 28);
        appendConvertedValue(nonce, recipientIndex);

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

    BYTE_ARRAY Base::generatePayloadSecretboxNonce(unsigned long packetIndex) {

        BYTE_ARRAY payloadSecretboxNonce = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 'p', 'l', 'o',
                                            'a', 'd', 's', 'b', '\0', '\0', '\0', '\0'};
        appendConvertedValue(payloadSecretboxNonce, packetIndex);

        return payloadSecretboxNonce;
    }

    BYTE_ARRAY Base::generateRecipientSecretboxNonce(unsigned long recipientIndex) {

        BYTE_ARRAY payloadSecretboxNonce = {'s', 'a', 'l', 't', 'p', 'a', 'c', 'k', '_', 'r', 'e', 'c',
                                            'i', 'p', 's', 'b', '\0', '\0', '\0', '\0'};
        appendConvertedValue(payloadSecretboxNonce, recipientIndex);

        return payloadSecretboxNonce;
    }

    BYTE_ARRAY
    Base::generateValueForSignature(unsigned long packetIndex, BYTE_ARRAY headerHash, BYTE_ARRAY message,
                                    BYTE_ARRAY flag) {

        // packet sequence
        BYTE_ARRAY packetSequence({0, 0, 0, 0});
        packetSequence.reserve(4);
        appendConvertedValue(packetSequence, packetIndex);

        // concatenate header hash, packet sequence, flag and payload chunk
        BYTE_ARRAY concat;
        concat.reserve(headerHash.size() + packetSequence.size() + message.size());
        concat.insert(concat.end(), headerHash.begin(), headerHash.end());
        concat.insert(concat.end(), packetSequence.begin(), packetSequence.end());
        concat.insert(concat.end(), flag.begin(), flag.end());
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

    BYTE_ARRAY Base::deriveSharedKey(BYTE_ARRAY publickey, BYTE_ARRAY secretkey) {

        BYTE_ARRAY sharedSymmetricKeyL(crypto_box_MACBYTES + ZEROES.size());
        if (crypto_box_easy(sharedSymmetricKeyL.data(), ZEROES.data(), ZEROES.size(), DERIVED_SBOX_KEY.data(),
                            publickey.data(), secretkey.data()) != 0)
            throw SaltpackException("Errors while generating shared symmetric key.");

        return BYTE_ARRAY(sharedSymmetricKeyL.end() - 32, sharedSymmetricKeyL.end());
    }

    BYTE_ARRAY Base::generateRecipientIdentifier(BYTE_ARRAY sharedSymmetricKey, BYTE_ARRAY payloadSecretboxNonce) {

        crypto_auth_hmacsha512_state state;
        BYTE_ARRAY concatHash = BYTE_ARRAY(crypto_auth_hmacsha512_BYTES);
        if (crypto_auth_hmacsha512_init(&state, SIGNCRYPTION_BOX_KEY_IDENTIFIER.data(),
                                        SIGNCRYPTION_BOX_KEY_IDENTIFIER.size()) != 0)
            throw SaltpackException("Errors while initializing HMAC.");
        if (crypto_auth_hmacsha512_update(&state, sharedSymmetricKey.data(), sharedSymmetricKey.size()) != 0)
            throw SaltpackException("Errors while updating HMAC.");
        if (crypto_auth_hmacsha512_update(&state, payloadSecretboxNonce.data(), payloadSecretboxNonce.size()) !=
            0)
            throw SaltpackException("Errors while updating HMAC.");
        if (crypto_auth_hmacsha512_final(&state, concatHash.data()) != 0)
            throw SaltpackException("Errors while calculating HMAC.");

        return BYTE_ARRAY(&concatHash[0], &concatHash[32]);
    }

    BYTE_ARRAY Base::deriveSharedKeySymmetric(BYTE_ARRAY publickey, BYTE_ARRAY secretkey) {

        crypto_auth_hmacsha512_state state;
        BYTE_ARRAY concatHash = BYTE_ARRAY(crypto_auth_hmacsha512_BYTES);
        if (crypto_auth_hmacsha512_init(&state, SIGNCRYPTION_DERIVED_SYMMETRIC_KEY.data(),
                                        SIGNCRYPTION_DERIVED_SYMMETRIC_KEY.size()) != 0)
            throw SaltpackException("Errors while initializing HMAC.");
        if (crypto_auth_hmacsha512_update(&state, publickey.data(), publickey.size()) != 0)
            throw SaltpackException("Errors while updating HMAC.");
        if (crypto_auth_hmacsha512_update(&state, secretkey.data(), secretkey.size()) !=
            0)
            throw SaltpackException("Errors while updating HMAC.");
        if (crypto_auth_hmacsha512_final(&state, concatHash.data()) != 0)
            throw SaltpackException("Errors while calculating HMAC.");

        return BYTE_ARRAY(&concatHash[0], &concatHash[32]);
    }

    BYTE_ARRAY Base::generateSigncryptionPacketNonce(BYTE_ARRAY headerHash, unsigned long packetIndex, bool final) {

        BYTE_ARRAY headerHashTrunc(&headerHash[0], &headerHash[16]);
        BYTE_ARRAY nonce;
        nonce.reserve(headerHashTrunc.size() + 8);
        nonce.insert(nonce.end(), headerHashTrunc.begin(), headerHashTrunc.end());
        nonce.insert(nonce.end(), ZEROES.begin(), ZEROES.end() - 28);
        appendConvertedValue(nonce, packetIndex);
        if (final)
            nonce[15] |= (BYTE) 1;
        else
            nonce[15] &= (BYTE) 254;

        return nonce;
    }

    BYTE_ARRAY
    Base::generateSignatureInput(BYTE_ARRAY packetNonce, BYTE_ARRAY headerHash, BYTE_ARRAY message, bool final) {

        // calculate hash of the plaintext
        BYTE_ARRAY hash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(hash.data(), message.data(), message.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        BYTE_ARRAY signatureInput;
        BYTE_ARRAY flag = BYTE_ARRAY(1);
        flag[0] = (BYTE) final;
        signatureInput.reserve(
                ENCRYPTED_SIGNATURE.size() + 1 + headerHash.size() + packetNonce.size() + flag.size() + hash.size());
        signatureInput.insert(signatureInput.end(), ENCRYPTED_SIGNATURE.begin(), ENCRYPTED_SIGNATURE.end());
        signatureInput.insert(signatureInput.end(), ZEROES.begin(), ZEROES.begin() + 1);
        signatureInput.insert(signatureInput.end(), headerHash.begin(), headerHash.end());
        signatureInput.insert(signatureInput.end(), packetNonce.begin(), packetNonce.end());
        signatureInput.insert(signatureInput.end(), flag.begin(), flag.end());
        signatureInput.insert(signatureInput.end(), hash.begin(), hash.end());

        return signatureInput;
    }
}
