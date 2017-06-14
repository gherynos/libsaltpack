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

#include <gtest/gtest.h>
#include <fstream>
#include <saltpack.h>
#include <sodium.h>

TEST(signature, attached) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, false);
    sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);

    out.flush();
    delete sig;

    // verify message
    std::stringstream in(out.str());
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(in);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }
    ASSERT_EQ(signer_publickey, dec->getSender());
    delete dec;

    ASSERT_EQ(msg.str(), "a signed message");
}

TEST(signature, attached_failure) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, false);
    sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);

    out.flush();
    delete sig;

    try {

        // verify message
        std::string mmsg = out.str();
        mmsg[mmsg.size() - 80] = (char)((int)mmsg[mmsg.size() - 80] + 1);
        std::stringstream in(mmsg);
        std::stringstream msg;
        saltpack::MessageReader dec(in);
        while (dec.hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec.getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Signature was forged or corrupt.");
    }
}

TEST(signature, attached_armor) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ATTACHED_SIGNATURE);
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, signer_secretkey, false);
    sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' '}, false);
    sig->addBlock({'m', 'e', 's', 's', 'a', 'g', 'e'}, true);
    aOut.finalise();

    out.flush();
    delete sig;

    // verify message
    std::stringstream in(out.str());
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(is);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }
    ASSERT_EQ(signer_publickey, dec->getSender());
    delete dec;

    ASSERT_EQ(msg.str(), "a signed message");
}

TEST(signature, detached) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, true);
    sig->addBlock({'T', 'h', '3', ' ', 'm'}, false);
    sig->addBlock({'E', '$', 's', '4', 'g', '['}, true);

    out.flush();
    delete sig;

    // verify message
    std::stringstream in(out.str());
    std::stringstream msg("Th3 mE$s4g[");
    saltpack::MessageReader *dec = new saltpack::MessageReader(in, msg);
    ASSERT_EQ(signer_publickey, dec->getSender());
    delete dec;

    try {

        std::stringstream in2(out.str());
        std::stringstream msg2("Wrong");
        saltpack::MessageReader(in2, msg2);

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Signature was forged or corrupt.");
    }
}

TEST(signature, detached_armor) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_DETACHED_SIGNATURE);
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, signer_secretkey, true);
    sig->addBlock({'T', 'h', '3', ' ', 'm', 'E', '$', 's', '4', 'g', '!'}, true);
    aOut.finalise();

    out.flush();
    delete sig;

    // verify message
    std::stringstream in(out.str());
    std::stringstream msg("Th3 mE$s4g!");
    saltpack::ArmoredInputStream is(in);
    saltpack::MessageReader *dec = new saltpack::MessageReader(is, msg);
    ASSERT_EQ(signer_publickey, dec->getSender());
    delete dec;

    try {

        std::stringstream in2(out.str());
        saltpack::ArmoredInputStream is2(in2);
        std::stringstream msg2("Wrong");
        saltpack::MessageReader(is2, msg2);

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Signature was forged or corrupt.");
    }
}

TEST(signature, attached_message_truncated) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, false);
    sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, false);

    out.flush();
    delete sig;

    try {

        // verify message
        std::stringstream in(out.str());
        std::stringstream msg;
        saltpack::MessageReader dec(in);
        while (dec.hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec.getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Not enough data found to decode block (message truncated?).");
    }
}

TEST(signature, detached_message_truncated) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    // sign message
    std::stringstream out;
    saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, true);
    sig->addBlock({'T', 'h', '3', ' ', 'm'}, false);
    sig->addBlock({'E', '$', 's', '4', 'g', '['}, false);

    out.flush();
    delete sig;

    try {

        // verify message
        std::stringstream in(out.str());
        std::stringstream msg("Th3 mE$s4g[");
        saltpack::MessageReader *dec = new saltpack::MessageReader(in, msg);
        ASSERT_EQ(signer_publickey, dec->getSender());
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Signature not found.");
    }
}

TEST(signature, attached_final_block) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    try {

        // sign message
        std::stringstream out;
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, false);
        sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
        sig->addBlock({' ', 'v', '2'}, true);

        out.flush();
        delete sig;

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Final block already added.");
    }
}

TEST(signature, detached_final_block) {

    saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
    saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
    saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);

    try {

        // sign message
        std::stringstream out;
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(out, signer_secretkey, true);
        sig->addBlock({'T', 'h', '3', ' ', 'm', 'E', '$', 's', '4', 'g', '!'}, true);
        sig->addBlock({'?'}, true);

        out.flush();
        delete sig;

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Final block already added.");
    }
}

TEST(signature, attached_version_one) {

    saltpack::BYTE_ARRAY signer_secretkey({245, 6, 38, 38, 136, 83, 114, 248, 171, 127, 74, 11, 45, 29, 126, 213, 7,
                                           236, 174, 197, 99, 201, 193, 207, 16, 91, 166, 133, 141, 50, 144, 211, 199,
                                           45, 196, 24, 141, 60, 173, 36, 11, 156, 148, 221, 212, 160, 252, 133, 136,
                                           160, 73, 11, 23, 129, 243, 218, 57, 180, 252, 17, 133, 46, 244, 139});
    saltpack::BYTE_ARRAY signer_publickey({199, 45, 196, 24, 141, 60, 173, 36, 11, 156, 148, 221, 212, 160, 252, 133,
                                           136, 160, 73, 11, 23, 129, 243, 218, 57, 180, 252, 17, 133, 46, 244, 139});

    std::string ciphertext = "BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G7KB2OUmwXTFd 8hHAxRyMXKWKOxs "
            "bECTM8qEn3zYPTA s94LWmdVgpRAw9I fxsGWxHAkkzEaL1 PfDAsXLp9Zq5ymY 5dySiZQZ5uC3IKy 9VGvkwoHiY8tLW1 "
            "iF5oHeppoqzIN0N 6ySAuKEqldHH8TL j4z3Q4x5C7Rp1lt 7uQljohrfLUO7qx 5EbIJbUQqM22Geh VFAaePwM5YjWGEg "
            "k2um83NphtgtIZQ fW0Aivnts1DYmJ7 bZHBN0yidHwJ2FY 5kmC0vApVJrJfni PwhFaGfjlMnghwS Y5G2v0olHriQMTV "
            "rEEy. END SALTPACK SIGNED MESSAGE.";

    // verify message
    std::stringstream in(ciphertext);
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(is);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }
    ASSERT_EQ(signer_publickey, dec->getSender());
    delete dec;

    ASSERT_EQ(msg.str(), "Signed message\n");
}

TEST(signature, detached_version_one) {

    saltpack::BYTE_ARRAY signer_secretkey({245, 6, 38, 38, 136, 83, 114, 248, 171, 127, 74, 11, 45, 29, 126, 213, 7,
                                           236, 174, 197, 99, 201, 193, 207, 16, 91, 166, 133, 141, 50, 144, 211, 199,
                                           45, 196, 24, 141, 60, 173, 36, 11, 156, 148, 221, 212, 160, 252, 133, 136,
                                           160, 73, 11, 23, 129, 243, 218, 57, 180, 252, 17, 133, 46, 244, 139});
    saltpack::BYTE_ARRAY signer_publickey({199, 45, 196, 24, 141, 60, 173, 36, 11, 156, 148, 221, 212, 160, 252, 133,
                                           136, 160, 73, 11, 23, 129, 243, 218, 57, 180, 252, 17, 133, 46, 244, 139});

    std::string ciphertext = "BEGIN SALTPACK DETACHED SIGNATURE. kYM5h1pg6qz9UMn j6G7KBABYp9npL6 oT1KkalFeaDwWxs "
            "bECTM8qEn3zYPTA s94LWmdVgpbwCki T35ZsJvycdnnkp5 xjaos54GAI71l9u lGzcrkDkh1iVWXY j8FY4EefSR9qMdi "
            "p8bqfMDseqX84Y2 5dtmyvwTiGQKs1O B40DzEV9VHZbchf PVh04NGL8rZHdQf 1wzeX5z. END SALTPACK DETACHED SIGNATURE.";

    // verify message
    std::stringstream in(ciphertext);
    std::stringstream msg("Signed message 2\n");
    saltpack::ArmoredInputStream is(in);
    saltpack::MessageReader *dec = new saltpack::MessageReader(is, msg);
    ASSERT_EQ(signer_publickey, dec->getSender());
    delete dec;
}
