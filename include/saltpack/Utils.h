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

#ifndef SALTPACK_UTILS_H
#define SALTPACK_UTILS_H

#include "types.h"

namespace saltpack {

    /**
     *  @brief Utilities class.
     */
    class Utils {

    public:
        /**
         * Generates an encryption keypair using `libsodium`.
         *
         * @param[out] publickey the public key array.
         * @param[out] secretkey the private key array.
         *
         * @throws SaltpackException
         */
        static void generateKeypair(BYTE_ARRAY &publickey, BYTE_ARRAY &secretkey);

        /**
         * Generates a signing keypair using `libsodium`.
         *
         * @param[out] publickey the public key array.
         * @param[out] secretkey the private key array.
         *
         * @throws SaltpackException
         */
        static void generateSignKeypair(BYTE_ARRAY &publickey, BYTE_ARRAY &secretkey);

        /**
         * Derives the public key from a private key.
         *
         * @param secretkey the private key.
         *
         * @throws SaltpackException
         *
         * @return the public key.
         */
        static BYTE_ARRAY derivePublickey(BYTE_ARRAY secretkey);

        /**
         * Returns the number of required characters to represent in BaseX, for a given `alphabet`, `size` characters.
         *
         * @param alphabet the alphabet for the BaseX encoding.
         * @param size the size of the data to represent.
         *
         * @return the number of characters required to encode `size` characters.
         */
        static int baseXblockSize(const std::string& alphabet, int size);

        /**
         * Encodes the data in BaseX using the given `alphabet`.
         *
         * @param data the data to encode.
         * @param alphabet the alphabet for the BaseX encoding.
         *
         * @return the encoded string.
         */
        static std::string baseXencode(const BYTE_ARRAY& data, std::string alphabet);

        /**
         * Encodes the data in BaseX using the given `alphabet`.
         *
         * @param data the data to encode.
         * @param size the number of characters to encode from `data`.
         * @param alphabet the alphabet for the BaseX encoding.
         *
         * @return the encoded string.
         */
        static std::string baseXencode(BYTE_ARRAY data, size_t size, std::string alphabet);

        /**
         * Decodes the string from BaseX and the given `alphabet`.
         *
         * @param data data the string to decode.
         * @param alphabet the alphabet for the BaseX decoding.
         *
         * @throws SaltpackException
         *
         * @return the decoded data.
         */
        static BYTE_ARRAY baseXdecode(std::string data, const std::string& alphabet);

        /**
         * Hexadecial to binary encoding.
         *
         * @param hex the hexadecimal string.
         *
         * @throws SaltpackException
         *
         * @return the binary data.
         */
        static BYTE_ARRAY hexToBin(const std::string& hex);

        /**
         * Binary to hexadecimal encoding.
         *
         * @param bin the binary data.
         *
         * @throws SaltpackException
         *
         * @return the hexadecimal string.
         */
        static std::string binToHex(BYTE_ARRAY bin);

        /**
         * Generates some random bytes using `libsodium`.
         *
         * @param size the amount of bytes to generate.
         *
         * @throws SaltpackException
         *
         * @return the random bytes.
         */
        static BYTE_ARRAY generateRandomBytes(size_t size);

        /**
         * Wrapper for the `crypto_pwhash` function from `libsodium`.
         *
         * @param keySize the size of the key.
         * @param password the password used to derive the key.
         * @param salt the salt used to derive the key.
         * @param opsLimit the maximum amount of computations to perform.
         * @param memLimit the maximum amount of RAM that the function will use, in bytes.
         *
         * @throws SaltpackException
         *
         * @return the derived key.
         */
        static BYTE_ARRAY deriveKeyFromPassword(unsigned long long int keySize, const std::string& password, BYTE_ARRAY salt,
                                                unsigned long long int opsLimit, size_t memLimit);
    };
}

#endif //SALTPACK_UTILS_H
