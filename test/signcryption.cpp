/*
 * Copyright 2017 Luca Zanconato
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
#include <fstream>
#include <saltpack.h>
#include <sodium.h>

TEST(signcryption, main) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    saltpack::BYTE_ARRAY receiver_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY receiver_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(receiver_publickey, receiver_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(receiver_publickey);

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;

    // signcrypt message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, recipients, symmetricKeys);
    sig->addBlock({'T', 'h', 'e', ' ', 'M', 'a', 'g', 'i', 'c', ' ', 'W', 'o', 'r', 'd', 's', ' ', 'a', 'r', 'e', ' '},
                  false);
    sig->addBlock({'S', 'q', 'u', 'e', 'a', 'm', 'i', 's', 'h', ' ', 'O', 's', 's', 'i', 'f', 'r', 'a', 'g', 'e'},
                  false);
    sig->addBlock({' ', ':', 'D'}, true);

    out.flush();
    delete sig;

    // verify message
    std::stringstream in(out.str());
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(in, receiver_secretkey,
                                                               std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(signer_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());
    delete dec;

    ASSERT_EQ(msg.str(), "The Magic Words are Squeamish Ossifrage :D");
}

TEST(signcryption, symmetric) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;
    std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY> key = std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>(
            saltpack::Utils::generateRandomBytes(32), saltpack::Utils::generateRandomBytes(crypto_secretbox_KEYBYTES));
    symmetricKeys.push_back(key);

    // signcrypt message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, recipients, symmetricKeys);
    sig->addBlock({'A', ' ', 'm', '3', 's', 'S', '@', 'g', '{'}, true);

    out.flush();
    delete sig;

    // verify message
    std::stringstream in(out.str());
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(in, saltpack::BYTE_ARRAY{}, key);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(signer_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());
    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g{");
}

TEST(signcryption, both) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    saltpack::BYTE_ARRAY receiver_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY receiver_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(receiver_publickey, receiver_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(receiver_publickey);

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;
    std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY> key = std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>(
            saltpack::Utils::generateRandomBytes(32), saltpack::Utils::generateRandomBytes(crypto_secretbox_KEYBYTES));
    symmetricKeys.push_back(key);

    // signcrypt message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, recipients, symmetricKeys);
    sig->addBlock({'A', ' '}, false);
    sig->addBlock({'m', '3', 's', 'S'}, false);
    sig->addBlock({'@', 'g', '{', '!', '}'}, true);

    out.flush();
    delete sig;

    // verify message with first key
    std::stringstream in(out.str());
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(in, saltpack::BYTE_ARRAY{}, key);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(signer_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());
    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g{!}");

    // verify message with second key
    std::stringstream in2(out.str());
    std::stringstream msg2;
    saltpack::MessageReader *dec2 = new saltpack::MessageReader(in2, receiver_secretkey,
                                                                std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});
    while (dec2->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec2->getBlock();
        msg2.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(signer_publickey, dec2->getSender());
    ASSERT_FALSE(dec2->isIntentionallyAnonymous());
    delete dec2;

    ASSERT_EQ(msg2.str(), "A m3sS@g{!}");
}

TEST(signcryption, both_armor) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    saltpack::BYTE_ARRAY receiver_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY receiver_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(receiver_publickey, receiver_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(receiver_publickey);

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;
    std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY> key = std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>(
            saltpack::Utils::generateRandomBytes(32), saltpack::Utils::generateRandomBytes(crypto_secretbox_KEYBYTES));
    symmetricKeys.push_back(key);

    // signcrypt message
    std::stringstream out;
    saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, signer_secretkey, recipients, symmetricKeys);
    sig->addBlock({'A', ' '}, false);
    sig->addBlock({'m', '3', 's', 'S'}, false);
    sig->addBlock({'@', 'g', '{', '!', '}'}, true);

    aOut.finalise();
    out.flush();
    delete sig;

    // verify message with first key
    std::stringstream in(out.str());
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(is, saltpack::BYTE_ARRAY{}, key);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(signer_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());
    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g{!}");

    // verify message with second key
    std::stringstream in2(out.str());
    saltpack::ArmoredInputStream is2(in2);
    std::stringstream msg2;
    saltpack::MessageReader *dec2 = new saltpack::MessageReader(is2, receiver_secretkey,
                                                                std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});
    while (dec2->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec2->getBlock();
        msg2.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(signer_publickey, dec2->getSender());
    ASSERT_FALSE(dec2->isIntentionallyAnonymous());
    delete dec2;

    ASSERT_EQ(msg2.str(), "A m3sS@g{!}");
}

TEST(signcryption, intentionally_anonymous) {

    saltpack::BYTE_ARRAY receiver_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY receiver_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(receiver_publickey, receiver_secretkey);

    saltpack::BYTE_ARRAY test_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY test_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(test_publickey, test_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(receiver_publickey);

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;
    std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY> key = std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>(
            saltpack::Utils::generateRandomBytes(32), saltpack::Utils::generateRandomBytes(crypto_secretbox_KEYBYTES));
    symmetricKeys.push_back(key);

    // signcrypt message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, recipients, symmetricKeys);
    sig->addBlock({'A', ' '}, false);
    sig->addBlock({'m', '3', 's', 'S'}, false);
    sig->addBlock({'@', 'g', '{', '?', '}'}, true);

    out.flush();
    delete sig;

    // verify message with first key
    std::stringstream in(out.str());
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(in, test_secretkey, key);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    saltpack::BYTE_ARRAY ZEROES = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0};

    ASSERT_EQ(dec->getSender(), ZEROES);
    ASSERT_TRUE(dec->isIntentionallyAnonymous());
    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g{?}");

    // verify message with second key
    std::stringstream in2(out.str());
    std::stringstream msg2;
    saltpack::MessageReader *dec2 = new saltpack::MessageReader(in2, receiver_secretkey,
                                                                std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});
    while (dec2->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec2->getBlock();
        msg2.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    ASSERT_EQ(dec2->getSender(), ZEROES);
    ASSERT_TRUE(dec2->isIntentionallyAnonymous());
    delete dec2;

    ASSERT_EQ(msg2.str(), "A m3sS@g{?}");
}

TEST(signcryption, final_block) {

    saltpack::BYTE_ARRAY signer_secretkey(
            {245, 6, 38, 38, 136, 83, 114, 248, 171, 127, 74, 11, 45, 29, 126, 213, 7, 236, 174, 197, 99, 201, 193, 207,
             16, 91, 166, 133, 141, 50, 144, 211, 199, 45, 196, 24, 141, 60, 173, 36, 11, 156, 148, 221, 212, 160, 252,
             133, 136, 160, 73, 11, 23, 129, 243, 218, 57, 180, 252, 17, 133, 46, 244, 139});
    saltpack::BYTE_ARRAY signer_publickey(
            {199, 45, 196, 24, 141, 60, 173, 36, 11, 156, 148, 221, 212, 160, 252, 133, 136, 160, 73, 11, 23, 129, 243,
             218, 57, 180, 252, 17, 133, 46, 244, 139});

    saltpack::BYTE_ARRAY receiver_publickey(
            {91, 60, 224, 67, 226, 67, 109, 110, 196, 207, 132, 190, 84, 111, 205, 96, 139, 110, 3, 81, 45, 115, 18,
             206, 191, 136, 220, 129, 246, 6, 90, 97});
    saltpack::BYTE_ARRAY receiver_secretkey(
            {85, 131, 78, 6, 239, 201, 214, 218, 57, 144, 74, 160, 101, 125, 235, 227, 102, 69, 143, 98, 84, 247, 106,
             182, 218, 66, 89, 131, 100, 113, 54, 169});

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(receiver_publickey);

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;

    try {

        // signcrypt message
        std::stringstream out;
        saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, signer_secretkey, recipients, symmetricKeys);
        sig->addBlock(
                {'T', 'h', 'e', ' ', 'M', 'a', 'g', 'i', 'c', ' ', 'W', 'o', 'r', 'd', 's', ' ', 'a', 'r', 'e', ' '},
                false);
        sig->addBlock({'S', 'q', 'u', 'e', 'a', 'm', 'i', 's', 'h', ' ', 'O', 's', 's', 'i', 'f', 'r', 'a', 'g', 'e'},
                      true);
        sig->addBlock({' ', ':', 'D'}, true);

        aOut.finalise();
        out.flush();
        delete sig;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Final block already added.");
    }

    std::string ciphertext = "BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHypuyyU k1mfdrvl6gJnQP1"
            "9Bcl3YCR3YDi6gZ YBdwyjQI91NQbpA 8GRPYAd2dQoYZOu KYkW7lAPxA4PNet kZmdoBlgIXnUUen uvQSFN9EGbu1hJH"
            "2qoymhKLQFW8YMV TQTX66Awj3l8mbS fqk0OAT1J0vwQzJ qLoswjE3ZqpaiBl Ebp2BK2Dt6gnv3N SBItnOBFsrcdUqG"
            "dE18T7Fqhrx6a0y KPYV4N27nqrOh4k swjXBFXN3xoK8Uc wBkE57vLjVVuCps rn2tmLPPDxswNxU BoQtDuQ6ZzxpuwV"
            "tqKpxMApAK3xj9o j8SSoqaDn0t2qQY gYt0rjtmn2PaJMa E7zTZoWOHq8accR vAPbhhSlEAH2hZe weYaXkx4znn1BCF"
            "nrKt40XmKnppFZh dnJBhSWk2In7tMn RsTBbvbDeNwA4D7 XWBKwe3nA8JLW94 wJ9RI9h4izPc7XY ZPqstbBhU1xhVeR"
            "PUwX8YI0NZd1ZGq RGLhcOMNz5a1x0F 6C5w1fBw534FhkO u4WJoyQJMS78OUr RM0dZFgVGqPqgIo zFiK5pwurWveY88"
            "ItC2nw9ekGJr7Hg mlkF6R9CL9AQDaF x8OmkxbT0EfulFi Ohd5vGxDGV6euLD. END SALTPACK ENCRYPTED MESSAGE.";

    try {

        // verify message
        std::stringstream in(ciphertext);
        saltpack::ArmoredInputStream is(in);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(is, receiver_secretkey,
                                                                   std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});

        saltpack::BYTE_ARRAY message;
        message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());

        message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());

        message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());

        ASSERT_EQ(signer_publickey, dec->getSender());
        ASSERT_FALSE(dec->isIntentionallyAnonymous());
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Final block already reached.");
    }
}

TEST(signcryption, truncated) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    saltpack::BYTE_ARRAY receiver_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY receiver_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(receiver_publickey, receiver_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(receiver_publickey);

    // keys
    std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;

    // signcrypt message
    std::stringstream out;
    saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, signer_secretkey, recipients, symmetricKeys);
    sig->addBlock({'T', 'h', 'e', ' ', 'M', 'a', 'g', 'i', 'c', ' ', 'W', 'o', 'r', 'd', 's', ' ', 'a', 'r', 'e', ' '},
                  false);
    sig->addBlock({'S', 'q', 'u', 'e', 'a', 'm', 'i', 's', 'h', ' ', 'O', 's', 's', 'i', 'f', 'r', 'a', 'g', 'e'},
                  false);
    sig->addBlock({' ', ':', 'D'}, false);

    aOut.finalise();
    out.flush();
    delete sig;

    try {

        // verify message
        std::stringstream in(out.str());
        saltpack::ArmoredInputStream is(in);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(is, receiver_secretkey,
                                                                   std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }

        ASSERT_EQ(signer_publickey, dec->getSender());
        ASSERT_FALSE(dec->isIntentionallyAnonymous());
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Not enough data found to decode block (message truncated?).");
    }
}
