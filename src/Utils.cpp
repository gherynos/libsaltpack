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

#include <cstddef>
#include <cmath>
#include <sodium.h>
#include "saltpack/Utils.h"
#include "saltpack/SaltpackException.h"
#include "../ext/Num/num.hpp"

namespace saltpack {

    void Utils::generateKeypair(BYTE_ARRAY &publickey, BYTE_ARRAY &secretkey) {

        if (secretkey.size() != crypto_box_SECRETKEYBYTES)
            throw SaltpackException("Wrong secretkey size.");

        if (publickey.size() != crypto_box_PUBLICKEYBYTES)
            throw SaltpackException("Wrong publickey size.");

        if (crypto_box_keypair(publickey.data(), secretkey.data()) != 0)
            throw SaltpackException("Errors while generating keypair.");
    }

    void Utils::generateSignKeypair(BYTE_ARRAY &publickey, BYTE_ARRAY &secretkey) {

        if (secretkey.size() != crypto_sign_SECRETKEYBYTES)
            throw SaltpackException("Wrong secretkey size.");

        if (publickey.size() != crypto_sign_PUBLICKEYBYTES)
            throw SaltpackException("Wrong publickey size.");

        if (crypto_sign_keypair(publickey.data(), secretkey.data()) != 0)
            throw SaltpackException("Errors while generating keypair.");
    }

    BYTE_ARRAY Utils::derivePublickey(BYTE_ARRAY secretkey) {

        if (secretkey.size() != crypto_box_SECRETKEYBYTES && secretkey.size() != crypto_sign_SECRETKEYBYTES)
            throw SaltpackException("Wrong secretkey size.");

        if (secretkey.size() == crypto_box_SECRETKEYBYTES) {

            BYTE_ARRAY publickey(crypto_box_PUBLICKEYBYTES);
            if (crypto_scalarmult_base(publickey.data(), secretkey.data()) != 0)
                throw SaltpackException("Errors while deriving public key.");

            return publickey;

        } else {

            BYTE_ARRAY publickey(crypto_sign_PUBLICKEYBYTES);
            if (crypto_sign_ed25519_sk_to_pk(publickey.data(), secretkey.data()) != 0)
                throw SaltpackException("Errors while deriving public key.");

            return publickey;
        }
    }

    int Utils::baseXblockSize(const std::string& alphabet, int size) {

        return (int) ceil(size * 8 / log2(alphabet.size()));
    }

    std::string Utils::baseXencode(const BYTE_ARRAY& data, std::string alphabet) {

        return baseXencode(data, data.size(), std::move(alphabet));
    }

    std::string Utils::baseXencode(BYTE_ARRAY data, size_t size, std::string alphabet) {

        int c = baseXblockSize(alphabet, (int) size);
        std::string out;

        Num num;
        for (size_t i = 0; i < size; i++) {

            num.mul_word(256);
            num.add_word(data.at(i));
        }

        for (int i = 0; i < c; i++) {

            Num::word remainder;
            Num::div_mod_half_word(num, alphabet.length(), num, remainder);
            out.insert(0, 1, alphabet.at(remainder));
        }

        return out;
    }

    BYTE_ARRAY Utils::baseXdecode(std::string data, const std::string& alphabet) {

        unsigned long a = alphabet.length();
        unsigned long c = data.length();
        auto b = (size_t) floor((double) c * log2(a) / 8);

        Num num(0);
        for (int i = (int) c - 1; i >= 0; i--) {

            num.mul_word(alphabet.length());
            num.add_word(alphabet.find(data.at(c - i - 1)));
        }

        BYTE_ARRAY out;
        while (num.size() > 0) {

            Num::word remainder;
            Num::div_mod_half_word(num, 256, num, remainder);
            out.push_back(remainder);
        }

        if (out.size() > b)
            throw SaltpackException("Illegal block.");

        out.resize(out.size() + (b - out.size()));
        std::reverse(out.begin(), out.end());

        return out;
    }

    BYTE_ARRAY Utils::hexToBin(const std::string& hex) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        BYTE_ARRAY out(hex.size() / 2);

        if (sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(), nullptr, nullptr, nullptr) != 0)
            throw SaltpackException("Unable to decode HEX string.");

        return out;
    }

    std::string Utils::binToHex(BYTE_ARRAY bin) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        std::vector<char> data(bin.size() * 2 + 1);

        if (sodium_bin2hex(data.data(), data.size(), bin.data(), bin.size()) == nullptr)
            throw SaltpackException("Unable to encode HEX string.");

        return {data.data()};
    }

    BYTE_ARRAY Utils::generateRandomBytes(size_t size) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        BYTE_ARRAY salt(size);
        randombytes_buf(salt.data(), size);

        return salt;
    }

    BYTE_ARRAY Utils::deriveKeyFromPassword(unsigned long long int keySize, const std::string& password, BYTE_ARRAY salt,
                                            unsigned long long int opsLimit, size_t memLimit) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        if (salt.size() != crypto_pwhash_SALTBYTES)
            throw SaltpackException("Wrong salt size.");

        BYTE_ARRAY key(keySize);

        if (crypto_pwhash(key.data(), keySize, password.c_str(), password.size(), salt.data(), opsLimit, memLimit,
                          crypto_pwhash_ALG_DEFAULT) != 0)
            throw SaltpackException("Errors while deriving key (out of memory).");

        return key;
    }
}
