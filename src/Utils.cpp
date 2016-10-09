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

#include <gmpxx.h>
#include <math.h>
#include <sodium.h>
#include "saltpack/Utils.h"
#include "saltpack/SaltpackException.h"

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

    int Utils::baseXblockSize(std::string alphabet, int size) {

        return (int) ceil(size * 8 / log2(alphabet.size()));
    }

    std::string Utils::baseXencode(BYTE_ARRAY data, std::string alphabet) {

        return baseXencode(data, data.size(), alphabet);
    }

    std::string Utils::baseXencode(BYTE_ARRAY data, size_t size, std::string alphabet) {

        unsigned long a = alphabet.length();
        int c = baseXblockSize(alphabet, (int) size);
        std::string out = "";

        mpz_class num;
        mpz_import(num.get_mpz_t(), size, 1, sizeof(BYTE), 1, 0, data.data());

        mpz_class bA(a);
        mpz_class mod;
        for (double i = 0; i < c; i++) {

            mpz_mod(mod.get_mpz_t(), num.get_mpz_t(), bA.get_mpz_t());
            out = alphabet.at(mod.get_ui()) + out;
            mpz_div(num.get_mpz_t(), num.get_mpz_t(), bA.get_mpz_t());
        }

        return out;
    }

    BYTE_ARRAY Utils::baseXdecode(std::string data, std::string alphabet) {

        unsigned long a = alphabet.length();
        unsigned long c = data.length();
        size_t b = (size_t) floor(c * log2(a) / 8);

        mpz_class num(0);
        mpz_class bA(a);
        mpz_class pow;
        for (int i = (int) c - 1; i >= 0; i--) {

            mpz_class digit((unsigned char) alphabet.find(data.at(c - i - 1)));

            mpz_pow_ui(pow.get_mpz_t(), bA.get_mpz_t(), (unsigned long) i);
            mpz_mul(digit.get_mpz_t(), digit.get_mpz_t(), pow.get_mpz_t());

            mpz_add(num.get_mpz_t(), num.get_mpz_t(), digit.get_mpz_t());
        }

        BYTE_ARRAY out((unsigned long) b);
        int numb = 8 * sizeof(BYTE);
        size_t count = (mpz_sizeinbase(num.get_mpz_t(), 2) + numb - 1) / numb;

        if (count > b)
            throw SaltpackException("Illegal block.");

        mpz_export(out.data() + (b - count), NULL, 1, sizeof(BYTE), 1, 0, num.get_mpz_t());

        return out;
    }

    BYTE_ARRAY Utils::hexToBin(std::string hex) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        BYTE_ARRAY out(hex.size() / 2);

        if (sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(), NULL, NULL, NULL) != 0)
            throw SaltpackException("Unable to decode HEX string.");

        return out;
    }

    std::string Utils::binToHex(BYTE_ARRAY bin) {

        if (sodium_init() == -1)
            throw SaltpackException("Unable to initialise libsodium.");

        std::vector<char> data(bin.size() * 2 + 1);

        if (sodium_bin2hex(data.data(), data.size(), bin.data(), bin.size()) == NULL)
            throw SaltpackException("Unable to encode HEX string.");

        return std::string(data.data());
    }
}
