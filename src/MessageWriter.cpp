/*
 * Copyright 2016-217 Luca Zanconato
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

#include <msgpack.hpp>
#include <iostream>
#include <sstream>
#include <sodium.h>
#include <fstream>
#include "saltpack/MessageWriter.h"
#include "saltpack/HeaderPacket.h"
#include "saltpack/SignatureHeaderPacket.h"
#include "saltpack/SignaturePayloadPacketV2.h"
#include "saltpack/PayloadPacketV2.h"
#include "saltpack/SigncryptionPayloadPacket.h"
#include "saltpack/SaltpackException.h"
#include "saltpack/Utils.h"
#include "saltpack/modes.h"

namespace saltpack {

    MessageWriter::MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, std::list<BYTE_ARRAY> recipients,
                                 bool visibleRecipients) : output(os) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        if (senderSecretkey.size() != 0 && senderSecretkey.size() != crypto_box_SECRETKEYBYTES)
            throw saltpack::SaltpackException("Wrong size for senderSecretKey");

        mode = MODE_ENCRYPTION;
        packetIndex = 0;
        lastBlockAdded = false;

        // generate random payload key
        payloadKey = BYTE_ARRAY(32);
        randombytes_buf(payloadKey.data(), payloadKey.size());

        // generate random ephemeral keypair
        BYTE_ARRAY ephemeralPublicKey(crypto_box_PUBLICKEYBYTES);
        BYTE_ARRAY ephemeralSecretkey(crypto_box_SECRETKEYBYTES);
        if (crypto_box_keypair(ephemeralPublicKey.data(), ephemeralSecretkey.data()) != 0)
            throw SaltpackException("Errors while generating keypair.");

        // intentionally anonymous message?
        BYTE_ARRAY senderPublickey;
        if (senderSecretkey.size() == 0) {

            senderSecretkey = ephemeralSecretkey;
            senderPublickey = ephemeralPublicKey;

        } else
            senderPublickey = Utils::derivePublickey(senderSecretkey);

        // generate header
        std::string header = generateEncryptionHeader(ephemeralSecretkey, ephemeralPublicKey, senderPublickey,
                                                      recipients, visibleRecipients);

        // encode header
        std::string header_enc = encodeHeader(header);
        output << header_enc;

        // generate header hash
        headerHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(headerHash.data(), (const unsigned char *) header.data(), header.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // generate mac keys for recipients
        BYTE_ARRAY headerHashTrunc(&headerHash[0], &headerHash[16]);
        int recipientIndex = 0;
        for (auto const &publickey : recipients) {

            macKeys.push_back(
                    generateMacKeyV2(headerHashTrunc, publickey, senderSecretkey, publickey, ephemeralSecretkey,
                                     recipientIndex));
            recipientIndex++;
        }
    }

    MessageWriter::MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, std::list<BYTE_ARRAY> recipients)
            : MessageWriter(os, senderSecretkey, recipients, true) {}

    MessageWriter::MessageWriter(std::ostream &os, std::list<BYTE_ARRAY> recipients, bool visibleRecipients)
            : MessageWriter(os, BYTE_ARRAY(0), recipients, visibleRecipients) {}

    MessageWriter::MessageWriter(std::ostream &os, std::list<BYTE_ARRAY> recipients) : MessageWriter(os, recipients,
                                                                                                     true) {}

    MessageWriter::MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey, bool detatchedSignature) : output(os) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        if (senderSecretkey.size() != crypto_sign_SECRETKEYBYTES)
            throw saltpack::SaltpackException("Wrong size for senderSecretkey");

        mode = detatchedSignature ? MODE_DETACHED_SIGNATURE : MODE_ATTACHED_SIGNATURE;
        packetIndex = 0;
        lastBlockAdded = false;

        // duplicate secret key
        secretKey.reserve(senderSecretkey.size());
        for (BYTE b: senderSecretkey)
            secretKey.push_back(b);

        // generate header
        BYTE_ARRAY senderPublickey = Utils::derivePublickey(senderSecretkey);
        std::string header = generateSignatureHeader(senderPublickey, detatchedSignature);

        // generate header hash
        headerHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(headerHash.data(), (const unsigned char *) header.data(), header.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        if (detatchedSignature) {

            // add header hash to the whole message
            buffer.reserve(headerHash.size());
            buffer.insert(buffer.end(), headerHash.begin(), headerHash.end());
        }

        // encode header
        std::string header_enc = encodeHeader(header);
        output << header_enc;
    }

    MessageWriter::MessageWriter(std::ostream &os, BYTE_ARRAY senderSecretkey,
                                 std::list<BYTE_ARRAY> recipientsPublickeys,
                                 std::list<std::pair<BYTE_ARRAY, BYTE_ARRAY>> symmetricalKeys) : output(os) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        if (senderSecretkey.size() != crypto_sign_SECRETKEYBYTES)
            throw saltpack::SaltpackException("Wrong size for senderSecretkey");

        mode = MODE_SIGNCRYPTION;
        packetIndex = 0;
        lastBlockAdded = false;

        // duplicate secret key
        secretKey.reserve(senderSecretkey.size());
        for (BYTE b: senderSecretkey)
            secretKey.push_back(b);

        // generate random payload key
        payloadKey = BYTE_ARRAY(32);
        randombytes_buf(payloadKey.data(), payloadKey.size());

        // generate random ephemeral keypair
        BYTE_ARRAY ephemeralPublicKey(crypto_box_PUBLICKEYBYTES);
        BYTE_ARRAY ephemeralSecretkey(crypto_box_SECRETKEYBYTES);
        if (crypto_box_keypair(ephemeralPublicKey.data(), ephemeralSecretkey.data()) != 0)
            throw SaltpackException("Errors while generating keypair.");

        // generate header
        BYTE_ARRAY senderPublickey = Utils::derivePublickey(senderSecretkey);
        std::string header = generateSigncryptionHeader(ephemeralSecretkey, ephemeralPublicKey, senderPublickey,
                                                        recipientsPublickeys, symmetricalKeys);

        // encode header
        std::string header_enc = encodeHeader(header);
        output << header_enc;

        // generate header hash
        headerHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(headerHash.data(), (const unsigned char *) header.data(), header.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");
    }

    MessageWriter::~MessageWriter() {

        sodium_memzero(payloadKey.data(), payloadKey.size());
        sodium_memzero(headerHash.data(), headerHash.size());
        sodium_memzero(secretKey.data(), secretKey.size());
        for (BYTE_ARRAY b: macKeys)
            sodium_memzero(b.data(), b.size());
        buffer.clear();
        buffer.shrink_to_fit();
    }

    std::string MessageWriter::generateEncryptionHeader(BYTE_ARRAY ephemeralSecretkey, BYTE_ARRAY ephemeralPublickey,
                                                        BYTE_ARRAY senderPublickey,
                                                        std::list<BYTE_ARRAY> recipientsPublickeys,
                                                        bool visibleRecipients) {

        // generate header packet
        HeaderPacket headerPacket;
        headerPacket.format = "saltpack";
        headerPacket.version = std::vector<int> {2, 0};
        headerPacket.mode = 0;
        headerPacket.ephemeralPublicKey = ephemeralPublickey;

        // generate sender secretbox
        headerPacket.senderSecretbox = BYTE_ARRAY(crypto_secretbox_MACBYTES + senderPublickey.size());
        if (crypto_secretbox_easy(headerPacket.senderSecretbox.data(), senderPublickey.data(), senderPublickey.size(),
                                  SENDER_KEY_NONCE.data(), payloadKey.data()) != 0)
            throw SaltpackException("Errors while calculating sender secretbox.");

        // recipients list
        headerPacket.recipientsList = std::vector<HeaderPacketRecipient>();
        headerPacket.recipientsList.reserve(recipientsPublickeys.size());
        int recipientIndex = 0;
        for (auto const &publickey : recipientsPublickeys) {

            HeaderPacketRecipient recipient;

            // generate payload nonce
            BYTE_ARRAY payloadSecretboxNonce = generateRecipientSecretboxNonce(recipientIndex);

            // generate payload key box for current recipient
            recipient.payloadKeyBox = BYTE_ARRAY(crypto_box_MACBYTES + payloadKey.size());
            if (crypto_box_easy(recipient.payloadKeyBox.data(), payloadKey.data(), payloadKey.size(),
                                payloadSecretboxNonce.data(),
                                publickey.data(), ephemeralSecretkey.data()) != 0)
                throw SaltpackException("Errors while calculating payload key box.");

            // public key
            if (visibleRecipients) {

                recipient.recipientPublicKey = publickey;

            } else
                recipient.recipientPublicKey = BYTE_ARRAY();

            headerPacket.recipientsList.push_back(recipient);
            recipientIndex++;
        }

        // serialise header
        msgpack::sbuffer buffer;
        msgpack::pack(buffer, headerPacket);

        return std::string(buffer.data(), buffer.size());
    }

    std::string MessageWriter::generateSignatureHeader(BYTE_ARRAY senderPublickey, bool detatchedSignature) {

        // generate header packet
        SignatureHeaderPacket headerPacket;
        headerPacket.format = "saltpack";
        headerPacket.version = std::vector<int> {2, 0};
        headerPacket.mode = detatchedSignature ? 2 : 1;
        headerPacket.senderPublicKey = senderPublickey;

        // generate random nonce
        headerPacket.nonce = BYTE_ARRAY(32);
        randombytes_buf(headerPacket.nonce.data(), headerPacket.nonce.size());

        // serialise header
        msgpack::sbuffer buffer;
        msgpack::pack(buffer, headerPacket);

        return std::string(buffer.data(), buffer.size());
    }

    std::string MessageWriter::generateSigncryptionHeader(BYTE_ARRAY ephemeralSecretkey, BYTE_ARRAY ephemeralPublickey,
                                                          BYTE_ARRAY senderPublickey,
                                                          std::list<BYTE_ARRAY> recipientsPublickeys,
                                                          std::list<std::pair<BYTE_ARRAY, BYTE_ARRAY>> symmetricalKeys) {

        // generate header packet
        HeaderPacket headerPacket;
        headerPacket.format = "saltpack";
        headerPacket.version = std::vector<int> {2, 0};
        headerPacket.mode = 3;
        headerPacket.ephemeralPublicKey = ephemeralPublickey;

        // generate sender secretbox
        headerPacket.senderSecretbox = BYTE_ARRAY(crypto_secretbox_MACBYTES + senderPublickey.size());
        if (crypto_secretbox_easy(headerPacket.senderSecretbox.data(), senderPublickey.data(), senderPublickey.size(),
                                  SENDER_KEY_NONCE.data(), payloadKey.data()) != 0)
            throw SaltpackException("Errors while calculating sender secretbox.");

        // recipients list
        headerPacket.recipientsList = std::vector<HeaderPacketRecipient>();
        headerPacket.recipientsList.reserve(recipientsPublickeys.size() + symmetricalKeys.size());
        int recipientIndex = 0;

        // process Curve25519 recipients
        for (auto const &publickey : recipientsPublickeys) {

            HeaderPacketRecipient recipient;

            // generate nonce
            BYTE_ARRAY payloadSecretboxNonce = generateRecipientSecretboxNonce(recipientIndex);

            // derive shared symmetric key
            BYTE_ARRAY sharedSymmetricKeyL(crypto_box_MACBYTES + ZEROES.size());
            if (crypto_box_easy(sharedSymmetricKeyL.data(), ZEROES.data(), ZEROES.size(), DERIVED_SBOX_KEY.data(),
                                publickey.data(), ephemeralSecretkey.data()) != 0)
                throw SaltpackException("Errors while generating shared symmetric key.");
            BYTE_ARRAY sharedSymmetricKey(&sharedSymmetricKeyL[sharedSymmetricKeyL.size() - 32],
                                          &sharedSymmetricKeyL[sharedSymmetricKeyL.size()]);

            // recipient identifier
            crypto_auth_hmacsha512_state state;
            BYTE_ARRAY concatHash = BYTE_ARRAY(crypto_auth_hmacsha512_BYTES);
            if (crypto_auth_hmacsha512_init(&state, SIGNCRYPTION_BOX_KEY_IDENTIFIER.data(),
                                            SIGNCRYPTION_BOX_KEY_IDENTIFIER.size()) != 0)
                throw SaltpackException("Errors while initialising HMAC.");
            if (crypto_auth_hmacsha512_update(&state, sharedSymmetricKey.data(), sharedSymmetricKey.size()) != 0)
                throw SaltpackException("Errors while updating HMAC.");
            if (crypto_auth_hmacsha512_update(&state, payloadSecretboxNonce.data(), payloadSecretboxNonce.size()) !=
                0)
                throw SaltpackException("Errors while updating HMAC.");
            if (crypto_auth_hmacsha512_final(&state, concatHash.data()) != 0)
                throw SaltpackException("Errors while calculating HMAC.");
            recipient.recipientPublicKey = BYTE_ARRAY(&concatHash[0], &concatHash[32]);

            // seal payload key
            recipient.payloadKeyBox = BYTE_ARRAY(crypto_secretbox_MACBYTES + payloadKey.size());
            if (crypto_secretbox_easy(recipient.payloadKeyBox.data(), payloadKey.data(), payloadKey.size(),
                                      payloadSecretboxNonce.data(), sharedSymmetricKey.data()) != 0)
                throw SaltpackException("Errors while encrypting data.");

            headerPacket.recipientsList.push_back(recipient);
            recipientIndex++;
        }

        // process symmetric key recipients
        for (auto const &keyPair : symmetricalKeys) {

            HeaderPacketRecipient recipient;

            // generate nonce
            BYTE_ARRAY payloadSecretboxNonce = generateRecipientSecretboxNonce(recipientIndex);

            // derive shared symmetric key
            crypto_auth_hmacsha512_state state;
            BYTE_ARRAY concatHash = BYTE_ARRAY(crypto_auth_hmacsha512_BYTES);
            if (crypto_auth_hmacsha512_init(&state, SIGNCRYPTION_DERIVED_SYMMETRIC_KEY.data(),
                                            SIGNCRYPTION_DERIVED_SYMMETRIC_KEY.size()) != 0)
                throw SaltpackException("Errors while initialising HMAC.");
            if (crypto_auth_hmacsha512_update(&state, ephemeralPublickey.data(), ephemeralPublickey.size()) != 0)
                throw SaltpackException("Errors while updating HMAC.");
            if (crypto_auth_hmacsha512_update(&state, keyPair.second.data(), keyPair.second.size()) !=
                0)
                throw SaltpackException("Errors while updating HMAC.");
            if (crypto_auth_hmacsha512_final(&state, concatHash.data()) != 0)
                throw SaltpackException("Errors while calculating HMAC.");
            BYTE_ARRAY sharedSymmetricKey(&concatHash[0], &concatHash[32]);

            // recipient identifier
            recipient.recipientPublicKey = keyPair.first;

            // seal payload key
            recipient.payloadKeyBox = BYTE_ARRAY(crypto_secretbox_MACBYTES + payloadKey.size());
            if (crypto_secretbox_easy(recipient.payloadKeyBox.data(), payloadKey.data(), payloadKey.size(),
                                      payloadSecretboxNonce.data(), sharedSymmetricKey.data()) != 0)
                throw SaltpackException("Errors while encrypting data.");

            headerPacket.recipientsList.push_back(recipient);
            recipientIndex++;
        }

        // serialise header
        msgpack::sbuffer buffer;
        msgpack::pack(buffer, headerPacket);

        return std::string(buffer.data(), buffer.size());
    }

    std::string MessageWriter::encodeHeader(std::string header) {

        // serialise the header into a MessagePack bin object
        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk2(&buffer);
        pk2.pack_bin((uint32_t) header.size());
        pk2.pack_bin_body(header.data(), (uint32_t) header.size());

        return std::string(buffer.data(), buffer.size());
    }

    BYTE_ARRAY MessageWriter::generateAuthenticator(BYTE_ARRAY concat, BYTE_ARRAY recipientMacKey) {

        // calculate hash
        BYTE_ARRAY concatHash(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(concatHash.data(), concat.data(), concat.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // generate authenticator for recipient
        BYTE_ARRAY authenticator(crypto_auth_BYTES);
        if (crypto_auth(authenticator.data(), concatHash.data(), concatHash.size(), recipientMacKey.data()) != 0)
            throw SaltpackException("Errors while calculating auth.");

        return authenticator;
    }

    void MessageWriter::addBlock(BYTE_ARRAY data, bool final) {

        // check block size
        if (data.size() > 1024 * 1024)
            throw SaltpackException("Blocks must be at most 1MB.");

        // check for final block already added
        if (final && lastBlockAdded)
            throw SaltpackException("Final block already added.");

        switch (mode) {

            case MODE_ENCRYPTION: {

                output << generatePayloadPacket(data, final);
            }
                break;

            case MODE_ATTACHED_SIGNATURE: {

                output << generateSignaturePayloadPacket(data, final);
            }
                break;

            case MODE_DETACHED_SIGNATURE: {

                buffer.reserve(data.size());
                buffer.insert(buffer.end(), data.begin(), data.end());

                if (final) {

                    // hash message
                    BYTE_ARRAY hash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
                    if (crypto_hash_sha512(hash.data(), (const unsigned char *) buffer.data(), buffer.size()) != 0)
                        throw SaltpackException("Errors while calculating hash.");

                    // concatenate SIGNATURE_DETACHED_SIGNATURE and hash
                    BYTE_ARRAY concat;
                    concat.reserve(SIGNATURE_DETACHED_SIGNATURE.size() + hash.size());
                    concat.insert(concat.end(), SIGNATURE_DETACHED_SIGNATURE.begin(),
                                  SIGNATURE_DETACHED_SIGNATURE.end());
                    concat.insert(concat.end(), hash.begin(), hash.end());

                    // sign
                    BYTE_ARRAY signature(crypto_sign_BYTES);
                    if (crypto_sign_detached(signature.data(), NULL, concat.data(), concat.size(), secretKey.data()) !=
                        0)
                        throw SaltpackException("Errors while signing message.");

                    // serialise packet
                    msgpack::sbuffer buffer;
                    msgpack::pack(buffer, signature);

                    output << std::string(buffer.data(), buffer.size());
                }
            }
                break;

            case MODE_SIGNCRYPTION: {

                output << generateSigncryptionPayloadPacket(data, final);
            }
                break;

            default:
                throw SaltpackException("Wrong mode.");
        }
    }

    std::string MessageWriter::generatePayloadPacket(BYTE_ARRAY message, bool final) {

        PayloadPacketV2 payloadPacket;

        // payload secret box nonce
        BYTE_ARRAY payloadSecretboxNonce = generatePayloadSecretboxNonce(packetIndex);

        // payload secret box
        payloadPacket.payloadSecretbox = BYTE_ARRAY(crypto_secretbox_MACBYTES + message.size());
        if (crypto_secretbox_easy(payloadPacket.payloadSecretbox.data(), (const unsigned char *) message.data(),
                                  message.size(),
                                  payloadSecretboxNonce.data(), payloadKey.data()) != 0)
            throw SaltpackException("Errors while encrypting data.");

        // concatenate header hash, payload secretbox nonce and payload secretbox
        BYTE_ARRAY concat;
        BYTE_ARRAY flag = BYTE_ARRAY(1);
        flag[0] = (BYTE) final;
        concat.reserve(
                headerHash.size() + payloadSecretboxNonce.size() + payloadPacket.payloadSecretbox.size() + flag.size());
        concat.insert(concat.end(), headerHash.begin(), headerHash.end());
        concat.insert(concat.end(), payloadSecretboxNonce.begin(), payloadSecretboxNonce.end());
        concat.insert(concat.end(), flag.begin(), flag.end());
        concat.insert(concat.end(), payloadPacket.payloadSecretbox.begin(), payloadPacket.payloadSecretbox.end());

        // authenticators
        payloadPacket.authenticatorsList = std::vector<BYTE_ARRAY>();
        payloadPacket.authenticatorsList.reserve(macKeys.size());
        for (auto const &mac_key : macKeys)
            payloadPacket.authenticatorsList.push_back(generateAuthenticator(concat, mac_key));
        payloadPacket.finalFlag = final;

        // serialise packet
        msgpack::sbuffer buffer;
        msgpack::pack(buffer, payloadPacket);

        packetIndex += 1;
        lastBlockAdded = final;

        return std::string(buffer.data(), buffer.size());
    }

    std::string MessageWriter::generateSignaturePayloadPacket(BYTE_ARRAY message, bool final) {

        SignaturePayloadPacketV2 payloadPacket;

        // payload chunk data
        payloadPacket.payloadChunk = message;

        // generate value for signature verification
        BYTE_ARRAY flag = BYTE_ARRAY(1);
        flag[0] = (BYTE) final;
        BYTE_ARRAY value = generateValueForSignature(packetIndex, headerHash, message, flag);

        // sign
        payloadPacket.signature = BYTE_ARRAY(crypto_sign_BYTES);
        if (crypto_sign_detached(payloadPacket.signature.data(), NULL, value.data(), value.size(),
                                 secretKey.data()) != 0)
            throw SaltpackException("Errors while signing message.");
        payloadPacket.finalFlag = final;

        // serialise packet
        msgpack::sbuffer buffer;
        msgpack::pack(buffer, payloadPacket);

        packetIndex += 1;
        lastBlockAdded = final;

        return std::string(buffer.data(), buffer.size());
    }

    std::string MessageWriter::generateSigncryptionPayloadPacket(BYTE_ARRAY message, bool final) {

        SigncryptionPayloadPacket payloadPacket;

        // packet nonce
        BYTE_ARRAY headerHashTrunc(&headerHash[0], &headerHash[16]);
        BYTE_ARRAY nonce;
        nonce.reserve(headerHashTrunc.size() + 8);
        nonce.insert(nonce.end(), headerHashTrunc.begin(), headerHashTrunc.end());
        nonce.push_back((BYTE) 0);
        nonce.push_back((BYTE) 0);
        nonce.push_back((BYTE) 0);
        nonce.push_back((BYTE) 0);
        nonce.push_back((BYTE) ((packetIndex >> 24) & 0xFF));
        nonce.push_back((BYTE) ((packetIndex >> 16) & 0xFF));
        nonce.push_back((BYTE) ((packetIndex >> 8) & 0XFF));
        nonce.push_back((BYTE) ((packetIndex & 0XFF)));
        if (final)
            nonce[15] |= (BYTE) 1;
        else
            nonce[15] &= (BYTE) 254;

        // calculate hash of the plaintext
        BYTE_ARRAY hash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(hash.data(), message.data(), message.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // signature input
        BYTE_ARRAY signatureInput;
        BYTE_ARRAY flag = BYTE_ARRAY(1);
        flag[0] = (BYTE) final;
        signatureInput.reserve(
                ENCRYPTED_SIGNATURE.size() + 1 + headerHash.size() + nonce.size() + flag.size() + hash.size());
        signatureInput.insert(signatureInput.end(), ENCRYPTED_SIGNATURE.begin(), ENCRYPTED_SIGNATURE.end());
        signatureInput.insert(signatureInput.end(), ZEROES.begin(), ZEROES.begin() + 1);
        signatureInput.insert(signatureInput.end(), headerHash.begin(), headerHash.end());
        signatureInput.insert(signatureInput.end(), nonce.begin(), nonce.end());
        signatureInput.insert(signatureInput.end(), flag.begin(), flag.end());
        signatureInput.insert(signatureInput.end(), hash.begin(), hash.end());

        // sign signature input
        BYTE_ARRAY signature(crypto_sign_BYTES);
        if (crypto_sign_detached(signature.data(), NULL, signatureInput.data(), signatureInput.size(),
                                 secretKey.data()) != 0)
            throw SaltpackException("Errors while signing input.");

        // message to encrypt
        BYTE_ARRAY concat;
        concat.reserve(signature.size() + message.size());
        concat.insert(concat.end(), signature.begin(), signature.end());
        concat.insert(concat.end(), message.begin(), message.end());

        // signcrypted chunk
        payloadPacket.signcryptedChunk = BYTE_ARRAY(crypto_secretbox_MACBYTES + concat.size());
        if (crypto_secretbox_easy(payloadPacket.signcryptedChunk.data(), (const unsigned char *) concat.data(),
                                  concat.size(),
                                  nonce.data(), payloadKey.data()) != 0)
            throw SaltpackException("Errors while encrypting data.");
        payloadPacket.finalFlag = final;

        // serialise packet
        msgpack::sbuffer buffer;
        msgpack::pack(buffer, payloadPacket);

        packetIndex += 1;
        lastBlockAdded = final;

        return std::string(buffer.data(), buffer.size());
    }
}
