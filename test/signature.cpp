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
