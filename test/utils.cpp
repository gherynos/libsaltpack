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

#include <gtest/gtest.h>
#include <saltpack.h>
#include <sodium.h>

TEST(utils, base_x) {

    saltpack::BYTE_ARRAY data = {0, 255};
    std::string enc = saltpack::Utils::baseXencode(data, "0123456789");

    ASSERT_EQ(enc, "00255");

    saltpack::BYTE_ARRAY dec = saltpack::Utils::baseXdecode(enc, "0123456789");

    ASSERT_EQ(data, dec);

    try {

        saltpack::Utils::baseXdecode("70000", "0123456789");
        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Illegal block.");
    }

    data = saltpack::BYTE_ARRAY(64);
    randombytes_buf(data.data(), data.size());

    enc = saltpack::Utils::baseXencode(data, saltpack::BASE85);
    dec = saltpack::Utils::baseXdecode(enc, saltpack::BASE85);

    ASSERT_EQ(data, dec);

    data = saltpack::BYTE_ARRAY(64);
    randombytes_buf(data.data(), data.size());

    enc = saltpack::Utils::baseXencode(data, saltpack::BASE62);
    dec = saltpack::Utils::baseXdecode(enc, saltpack::BASE62);

    ASSERT_EQ(data, dec);

    data = saltpack::BYTE_ARRAY(64);
    randombytes_buf(data.data(), data.size());

    enc = saltpack::Utils::baseXencode(data, saltpack::BASE64);
    dec = saltpack::Utils::baseXdecode(enc, saltpack::BASE64);

    ASSERT_EQ(data, dec);
}

TEST(utils, hex) {

    saltpack::BYTE_ARRAY data(64);
    randombytes_buf(data.data(), data.size());

    std::string enc = saltpack::Utils::binToHex(data);
    saltpack::BYTE_ARRAY dec = saltpack::Utils::hexToBin(enc);

    ASSERT_EQ(data, dec);
}

TEST(utils, derive_key) {

    saltpack::BYTE_ARRAY salt = saltpack::Utils::generateRandomBytes(crypto_pwhash_SALTBYTES);

    saltpack::BYTE_ARRAY key = saltpack::Utils::deriveKeyFromPassword(64, "Simple password", salt,
                                                                      crypto_pwhash_OPSLIMIT_MODERATE,
                                                                      crypto_pwhash_MEMLIMIT_MODERATE);

    ASSERT_EQ(key.size(), (unsigned int) 64);

    saltpack::BYTE_ARRAY key2 = saltpack::Utils::deriveKeyFromPassword(64, "Simple password2", salt,
                                                                       crypto_pwhash_OPSLIMIT_MODERATE,
                                                                       crypto_pwhash_MEMLIMIT_MODERATE);

    ASSERT_EQ(key2.size(), (unsigned int) 64);
    ASSERT_NE(key, key2);

    salt = saltpack::Utils::generateRandomBytes(crypto_pwhash_SALTBYTES);
    saltpack::BYTE_ARRAY key3 = saltpack::Utils::deriveKeyFromPassword(64, "Simple password", salt,
                                                                       crypto_pwhash_OPSLIMIT_MODERATE,
                                                                       crypto_pwhash_MEMLIMIT_MODERATE);

    ASSERT_EQ(key3.size(), (unsigned int) 64);
    ASSERT_NE(key, key3);
}
