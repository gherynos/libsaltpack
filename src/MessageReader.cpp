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

#include <msgpack.hpp>
#include <iostream>
#include <sstream>
#include <sodium.h>
#include "saltpack/Utils.h"
#include "saltpack/SignaturePayloadPacketV2.h"
#include "saltpack/SigncryptionPayloadPacket.h"
#include "saltpack/MessageReader.h"
#include "saltpack/HeaderPacket.h"
#include "saltpack/SaltpackException.h"
#include "saltpack/modes.h"
#include "saltpack/SignatureHeaderPacket.h"

namespace saltpack {

    const int BUFFER_SIZE = 512;

    MessageReader::MessageReader(std::istream &is, const BYTE_ARRAY& recipientSecretkey) : input(is) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        if (recipientSecretkey.size() != crypto_box_SECRETKEYBYTES)
            throw saltpack::SaltpackException("Wrong size for recipientSecretkey.");

        std::vector<char> headerBin;
        while (!input.eof()) {

            // read buffer
            unpacker.reserve_buffer(BUFFER_SIZE);
            input.read(unpacker.buffer(), BUFFER_SIZE);
            long count = input.gcount();
            unpacker.buffer_consumed((size_t) count);

            // try to extract object
            msgpack::object_handle oh;
            if (unpacker.next(oh)) {

                oh.get().convert(headerBin);
                break;
            }
        }

        macKey = BYTE_ARRAY(32);
        mode = MODE_ENCRYPTION;
        processEncryptionHeader(headerBin, recipientSecretkey);

        packetIndex = 0;
        lastBlockFound = false;
    }

    MessageReader::MessageReader(std::istream &is) : input(is) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        std::vector<char> headerBin;
        while (!input.eof()) {

            // read buffer
            unpacker.reserve_buffer(BUFFER_SIZE);
            input.read(unpacker.buffer(), BUFFER_SIZE);
            long count = input.gcount();
            unpacker.buffer_consumed((size_t) count);

            // try to extract object
            msgpack::object_handle oh;
            if (unpacker.next(oh)) {

                oh.get().convert(headerBin);
                break;
            }
        }

        mode = MODE_ATTACHED_SIGNATURE;
        processSignatureHeader(headerBin);

        packetIndex = 0;
        lastBlockFound = false;
    }

    MessageReader::MessageReader(std::istream &is, std::istream &messageStream) : input(is) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        std::vector<char> headerBin;
        BYTE_ARRAY signature;
        while (!input.eof()) {

            // read buffer
            unpacker.reserve_buffer(BUFFER_SIZE);
            input.read(unpacker.buffer(), BUFFER_SIZE);
            long count = input.gcount();
            unpacker.buffer_consumed((size_t) count);

            // try to extract object
            msgpack::object_handle oh;
            while (unpacker.next(oh)) {

                if (headerBin.empty())
                    oh.get().convert(headerBin);
                else {

                    oh.get().convert(signature);
                    break;
                }
            }
        }
        if (signature.empty())
            throw SaltpackException("Signature not found.");

        // process header
        mode = MODE_DETACHED_SIGNATURE;
        processSignatureHeader(headerBin);

        // append header to message
        std::stringstream message;
        message.write(reinterpret_cast<char *>(headerHash.data()), headerHash.size());

        // load message
        std::vector<char> buf(BUFFER_SIZE);
        while (!messageStream.eof()) {

            messageStream.read(buf.data(), BUFFER_SIZE);
            long count = messageStream.gcount();

            message.write(buf.data(), count);
        }
        std::string m = message.str();

        // hash message
        BYTE_ARRAY hash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(hash.data(), (const unsigned char *) m.data(), m.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // concatenate SIGNATURE_DETACHED_SIGNATURE and hash
        BYTE_ARRAY concat;
        concat.reserve(SIGNATURE_DETACHED_SIGNATURE.size() + hash.size());
        concat.insert(concat.end(), SIGNATURE_DETACHED_SIGNATURE.begin(), SIGNATURE_DETACHED_SIGNATURE.end());
        concat.insert(concat.end(), hash.begin(), hash.end());

        // verify signature
        if (crypto_sign_verify_detached(signature.data(), concat.data(), concat.size(), senderPublickey.data()) != 0)
            throw SaltpackException("Signature was forged or corrupt.");
    }

    MessageReader::MessageReader(std::istream &is, const BYTE_ARRAY& recipientSecretkey,
                                 const std::pair<BYTE_ARRAY, BYTE_ARRAY>& symmetricKey) : input(is) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        if (!recipientSecretkey.empty() && recipientSecretkey.size() != crypto_box_SECRETKEYBYTES)
            throw saltpack::SaltpackException("Wrong size for recipientSecretkey.");

        if (!symmetricKey.first.empty() && symmetricKey.second.size() != crypto_secretbox_KEYBYTES)
            throw saltpack::SaltpackException("Wrong size for symmetricKey.");

        std::vector<char> headerBin;
        while (!input.eof()) {

            // read buffer
            unpacker.reserve_buffer(BUFFER_SIZE);
            input.read(unpacker.buffer(), BUFFER_SIZE);
            long count = input.gcount();
            unpacker.buffer_consumed((size_t) count);

            // try to extract object
            msgpack::object_handle oh;
            if (unpacker.next(oh)) {

                oh.get().convert(headerBin);
                break;
            }
        }

        macKey = BYTE_ARRAY(32);
        mode = MODE_SIGNCRYPTION;
        processSigncryptionHeader(headerBin, recipientSecretkey, symmetricKey);

        packetIndex = 0;
        lastBlockFound = false;
    }

    MessageReader::~MessageReader() {

        sodium_memzero(headerHash.data(), headerHash.size());
        sodium_memzero(payloadKey.data(), payloadKey.size());
        sodium_memzero(macKey.data(), macKey.size());
        sodium_memzero(senderPublickey.data(), senderPublickey.size());
        for (BYTE_ARRAY recipient: recipients)
            sodium_memzero(recipient.data(), recipient.size());
    }

    void MessageReader::processEncryptionHeader(std::vector<char> headerBin, BYTE_ARRAY recipientSecretkey) {

        // generate header hash
        headerHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(headerHash.data(), (const unsigned char *) headerBin.data(), headerBin.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // deserialize header packet
        msgpack::object_handle oh = msgpack::unpack(headerBin.data(), headerBin.size());
        msgpack::object obj = oh.get();
        HeaderPacket header;
        obj.convert(header);

        // sanity check
        if (header.format != "saltpack") {

            std::ostringstream stringStream;
            stringStream << "Unrecognized format name: " << header.format << ".";
            throw SaltpackException(stringStream.str());
        }
        majorVersion = header.version[0];
        minorVersion = header.version[1];
        if ((majorVersion != 1 && majorVersion != 2) || minorVersion != 0) {

            std::ostringstream stringStream;
            stringStream << "Incompatible version: " << majorVersion << "." << minorVersion << ".";
            throw SaltpackException(stringStream.str());
        }
        if (header.mode != mode)
            throw SaltpackException("Wrong mode.");

        // pre-compute the ephemeral shared secret
        BYTE_ARRAY k(crypto_box_BEFORENMBYTES);
        if (crypto_box_beforenm(k.data(), header.ephemeralPublicKey.data(), recipientSecretkey.data()) != 0)
            throw SaltpackException("Errors during key pre-calculation.");

        // try to open the key boxes
        recipientIndex = header.recipientsList.size();
        payloadKey = BYTE_ARRAY(32);
        for (unsigned long i = 0; i < header.recipientsList.size(); i++) {

            BYTE_ARRAY nonce = PAYLOAD_KEY_BOX_NONCE;
            if (majorVersion == 2)
                nonce = generateRecipientSecretboxNonce(i);

            if (crypto_box_open_easy_afternm(payloadKey.data(), header.recipientsList[i].payloadKeyBox.data(),
                                             header.recipientsList[i].payloadKeyBox.size(),
                                             nonce.data(), k.data()) == 0) {

                recipientIndex = i;
            }

            recipients.push_back(header.recipientsList[i].recipientPublicKey);
        }

        if (recipientIndex != header.recipientsList.size()) {

            // open the sender secretbox
            senderPublickey = BYTE_ARRAY(crypto_box_PUBLICKEYBYTES);
            if (crypto_secretbox_open_easy(senderPublickey.data(), header.senderSecretbox.data(),
                                           header.senderSecretbox.size(), SENDER_KEY_NONCE.data(), payloadKey.data()) !=
                0)
                throw SaltpackException("Errors while getting sender public key.");

            // intentionally anonymous message?
            intentionallyAnonymous = header.ephemeralPublicKey == senderPublickey;

            // generate mac key
            if (majorVersion == 1) {

                BYTE_ARRAY headerHashTrunc(&headerHash[0], &headerHash[24]);
                macKey = generateMacKey(headerHashTrunc, senderPublickey, recipientSecretkey);

            } else if (majorVersion == 2) {

                BYTE_ARRAY headerHashTrunc(&headerHash[0], &headerHash[16]);
                macKey = generateMacKeyV2(headerHashTrunc, senderPublickey, recipientSecretkey,
                                          header.ephemeralPublicKey, recipientSecretkey, recipientIndex);
            }

        } else
            throw SaltpackException("Failed to find matching recipient.");
    }

    void MessageReader::processSignatureHeader(std::vector<char> headerBin) {

        // generate header hash
        headerHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(headerHash.data(), (const unsigned char *) headerBin.data(), headerBin.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // deserialize header packet
        msgpack::object_handle oh = msgpack::unpack(headerBin.data(), headerBin.size());
        msgpack::object obj = oh.get();
        SignatureHeaderPacket header;
        obj.convert(header);

        // sanity check
        if (header.format != "saltpack") {

            std::ostringstream stringStream;
            stringStream << "Unrecognized format name: " << header.format << ".";
            throw SaltpackException(stringStream.str());
        }
        majorVersion = header.version[0];
        minorVersion = header.version[1];
        if ((majorVersion != 1 && majorVersion != 2) || minorVersion != 0) {

            std::ostringstream stringStream;
            stringStream << "Incompatible version: " << majorVersion << "." << minorVersion << ".";
            throw SaltpackException(stringStream.str());
        }
        if (header.mode != mode)
            throw SaltpackException("Wrong mode.");

        senderPublickey = header.senderPublicKey;
    }

    void MessageReader::processSigncryptionHeader(std::vector<char> headerBin, const BYTE_ARRAY& recipientSecretkey,
                                                  const std::pair<BYTE_ARRAY, BYTE_ARRAY>& symmetricKey) {

        // generate header hash
        headerHash = BYTE_ARRAY(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(headerHash.data(), (const unsigned char *) headerBin.data(), headerBin.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // deserialize header packet
        msgpack::object_handle oh = msgpack::unpack(headerBin.data(), headerBin.size());
        msgpack::object obj = oh.get();
        HeaderPacket header;
        obj.convert(header);

        // sanity check
        if (header.format != "saltpack") {

            std::ostringstream stringStream;
            stringStream << "Unrecognized format name: " << header.format << ".";
            throw SaltpackException(stringStream.str());
        }
        majorVersion = header.version[0];
        minorVersion = header.version[1];
        if (majorVersion != 2 || minorVersion != 0) {

            std::ostringstream stringStream;
            stringStream << "Incompatible version: " << majorVersion << "." << minorVersion << ".";
            throw SaltpackException(stringStream.str());
        }
        if (header.mode != mode)
            throw SaltpackException("Wrong mode.");

        recipientIndex = header.recipientsList.size();
        payloadKey = BYTE_ARRAY(32);
        BYTE_ARRAY sharedSymmetricKey;
        if (!recipientSecretkey.empty()) {

            // derive shared symmetric key
            sharedSymmetricKey = deriveSharedKey(header.ephemeralPublicKey, recipientSecretkey);

            // try to open the key boxes with Curve25519 key
            for (unsigned long i = 0; i < header.recipientsList.size(); i++) {

                // generate nonce
                BYTE_ARRAY payloadSecretboxNonce = generateRecipientSecretboxNonce(i);

                // compute and verify identifier
                BYTE_ARRAY identifier = generateRecipientIdentifier(sharedSymmetricKey, payloadSecretboxNonce);
                if (identifier == header.recipientsList[i].recipientPublicKey) {

                    recipientIndex = i;
                }

                recipients.push_back(header.recipientsList[i].recipientPublicKey);
            }
        }

        if (recipientIndex == header.recipientsList.size() && !symmetricKey.first.empty()) {

            // look for symmetric key identifier
            for (unsigned long i = 0; i < header.recipientsList.size(); i++) {

                if (symmetricKey.first == header.recipientsList[i].recipientPublicKey) {

                    recipientIndex = i;

                    // derive shared symmetric key
                    sharedSymmetricKey = deriveSharedKeySymmetric(header.ephemeralPublicKey, symmetricKey.second);
                }

                if (recipientSecretkey.empty())
                    recipients.push_back(header.recipientsList[i].recipientPublicKey);
            }
        }

        if (recipientIndex != header.recipientsList.size()) {

            BYTE_ARRAY payloadSecretboxNonce = generateRecipientSecretboxNonce(recipientIndex);

            // decrypt payload key
            if (crypto_secretbox_open_easy(payloadKey.data(),
                                           header.recipientsList[recipientIndex].payloadKeyBox.data(),
                                           header.recipientsList[recipientIndex].payloadKeyBox.size(),
                                           payloadSecretboxNonce.data(), sharedSymmetricKey.data()) != 0)
                throw SaltpackException("Errors while getting payload key.");

            // open the sender secretbox
            senderPublickey = BYTE_ARRAY(crypto_box_PUBLICKEYBYTES);
            if (crypto_secretbox_open_easy(senderPublickey.data(), header.senderSecretbox.data(),
                                           header.senderSecretbox.size(), SENDER_KEY_NONCE.data(), payloadKey.data()) !=
                0)
                throw SaltpackException("Errors while getting sender public key.");

            // intentionally anonymous message?
            intentionallyAnonymous = senderPublickey == ZEROES;

        } else
            throw SaltpackException("Failed to find matching recipient.");
    }

    BYTE_ARRAY MessageReader::getBlock() {

        if (mode != MODE_ENCRYPTION && mode != MODE_ATTACHED_SIGNATURE && mode != MODE_SIGNCRYPTION)
            throw SaltpackException("Wrong mode.");

        // check for final block already parsed
        if (lastBlockFound)
            throw SaltpackException("Final block already reached.");

        // try to extract object
        msgpack::object_handle oh;
        bool found = false;
        if (!unpacker.next(oh)) {

            while (!input.eof()) {

                // read buffer
                unpacker.reserve_buffer(BUFFER_SIZE);
                input.read(unpacker.buffer(), BUFFER_SIZE);
                long count = input.gcount();
                unpacker.buffer_consumed((size_t) count);

                if (unpacker.next(oh)) {

                    found = true;
                    break;
                }
            }

        } else
            found = true;

        if (!found)
            throw SaltpackException("Not enough data found to decode block (message truncated?).");

        switch (mode) {

            case MODE_ENCRYPTION: {

                // decrypt packet
                if (majorVersion == 1) {

                    PayloadPacket packet;
                    oh.get().convert(packet);
                    return decryptPacket(packet.authenticatorsList, packet.payloadSecretbox, true);

                } else if (majorVersion == 2) {

                    PayloadPacketV2 packet;
                    oh.get().convert(packet);
                    return decryptPacket(packet.authenticatorsList, packet.payloadSecretbox, packet.finalFlag);

                } else
                    throw SaltpackException("Wrong version.");
            }

            case MODE_ATTACHED_SIGNATURE: {

                // verify packet
                if (majorVersion == 1) {

                    SignaturePayloadPacket packet;
                    oh.get().convert(packet);
                    return verifyPacket(packet.signature, packet.payloadChunk, true);

                } else if (majorVersion == 2) {

                    SignaturePayloadPacketV2 packet;
                    oh.get().convert(packet);
                    return verifyPacket(packet.signature, packet.payloadChunk, packet.finalFlag);

                } else
                    throw SaltpackException("Wrong version.");
            }

            case MODE_SIGNCRYPTION: {

                // decrypt packet
                SigncryptionPayloadPacket packet;
                oh.get().convert(packet);
                return decryptPacket(packet.signcryptedChunk, packet.finalFlag);
            }

            default:
                throw SaltpackException("Wrong mode.");
        }
    }

    BYTE_ARRAY
    MessageReader::decryptPacket(std::vector<BYTE_ARRAY> authenticatorsList, BYTE_ARRAY payloadSecretbox, bool final) {

        // payload secret box nonce
        BYTE_ARRAY payloadSecretboxNonce = generatePayloadSecretboxNonce(packetIndex);

        // final flag (if applicable)
        BYTE_ARRAY flag;
        if (majorVersion == 2) {

            flag = BYTE_ARRAY(1);
            flag[0] = (BYTE) final;

        } else
            flag = BYTE_ARRAY(0);

        // concatenate header hash, payload secretbox nonce, final flag and payload secretbox
        BYTE_ARRAY concat;
        concat.reserve(
                headerHash.size() + payloadSecretboxNonce.size() + payloadSecretbox.size() + flag.size());
        concat.insert(concat.end(), headerHash.begin(), headerHash.end());
        concat.insert(concat.end(), payloadSecretboxNonce.begin(), payloadSecretboxNonce.end());
        concat.insert(concat.end(), flag.begin(), flag.end());
        concat.insert(concat.end(), payloadSecretbox.begin(), payloadSecretbox.end());

        // calculate hash
        BYTE_ARRAY concatHash(crypto_hash_sha512_BYTES);
        if (crypto_hash_sha512(concatHash.data(), concat.data(), concat.size()) != 0)
            throw SaltpackException("Errors while calculating hash.");

        // verify authenticator
        if (crypto_auth_verify(authenticatorsList[recipientIndex].data(), concatHash.data(), concatHash.size(),
                               macKey.data()) != 0)
            throw SaltpackException("Invalid authenticator.");

        // decrypt payload
        BYTE_ARRAY message(payloadSecretbox.size() - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(message.data(), payloadSecretbox.data(), payloadSecretbox.size(),
                                       payloadSecretboxNonce.data(), payloadKey.data()) != 0)
            throw SaltpackException("Errors while decrypting payload.");

        if (majorVersion == 2 || (majorVersion == 1 && !message.empty()))
            packetIndex += 1;
        lastBlockFound = majorVersion == 2 ? final : message.empty();

        return message;
    }

    BYTE_ARRAY MessageReader::verifyPacket(BYTE_ARRAY signature, BYTE_ARRAY payloadChunk, bool final) {

        // final flag (if applicable)
        BYTE_ARRAY flag;
        if (majorVersion == 2) {

            flag = BYTE_ARRAY(1);
            flag[0] = (BYTE) final;

        } else
            flag = BYTE_ARRAY(0);

        // generate value for signature verification
        BYTE_ARRAY value = generateValueForSignature(packetIndex, headerHash, payloadChunk, flag);

        // verify signature
        if (crypto_sign_verify_detached(signature.data(), value.data(), value.size(), senderPublickey.data()) != 0)
            throw SaltpackException("Signature was forged or corrupt.");

        if (majorVersion == 2 || (majorVersion == 1 && !payloadChunk.empty()))
            packetIndex += 1;
        lastBlockFound = majorVersion == 2 ? final : payloadChunk.empty();

        return payloadChunk;
    }

    BYTE_ARRAY MessageReader::decryptPacket(BYTE_ARRAY payloadSecretbox, bool final) {

        // packet nonce
        BYTE_ARRAY nonce = generateSigncryptionPacketNonce(headerHash, packetIndex, final);

        // decrypt chunk
        BYTE_ARRAY chunk(payloadSecretbox.size() - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(chunk.data(), payloadSecretbox.data(), payloadSecretbox.size(), nonce.data(),
                                       payloadKey.data()) != 0)
            throw SaltpackException("Errors while decrypting payload.");

        // extract signature and message from chunk
        BYTE_ARRAY detachedSignature(&chunk[0], &chunk[64]);
        BYTE_ARRAY message(&chunk[64], &chunk[chunk.size()]);

        // compute the signature input
        BYTE_ARRAY signatureInput = generateSignatureInput(nonce, headerHash, message, final);

        if (!intentionallyAnonymous) {

            // verify the signature
            if (crypto_sign_verify_detached(detachedSignature.data(), signatureInput.data(), signatureInput.size(),
                                            senderPublickey.data()) != 0)
                throw SaltpackException("Signature was forged or corrupt.");
        }

        packetIndex += 1;
        lastBlockFound = final;

        return message;
    }

    bool MessageReader::hasMoreBlocks() {

        if (mode != MODE_ENCRYPTION && mode != MODE_ATTACHED_SIGNATURE && mode != MODE_SIGNCRYPTION)
            throw SaltpackException("Wrong mode.");

        return !lastBlockFound;
    }

    std::list<BYTE_ARRAY> MessageReader::getRecipients() {

        return recipients;
    }

    BYTE_ARRAY MessageReader::getSender() {

        return senderPublickey;
    }

    bool MessageReader::isIntentionallyAnonymous() {

        if (mode != MODE_ENCRYPTION && mode != MODE_SIGNCRYPTION)
            throw SaltpackException("Wrong mode.");

        return intentionallyAnonymous;
    }
}
