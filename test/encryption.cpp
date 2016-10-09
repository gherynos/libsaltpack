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

TEST(encryption, main) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(sender_publickey);
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    saltpack::MessageWriter *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
    enc->addBlock({'A', ' '});
    enc->addBlock({'m', '3', 's', 'S'});
    enc->addBlock({'@', 'g', '{'});
    enc->finalise();

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(in, recipient_secretkey);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }
    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g{");
}

TEST(encryption, failure_recipient) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(sender_publickey);

    // encrypt message
    std::stringstream out;

    saltpack::MessageWriter *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
    enc->addBlock({'A', ' '});
    enc->addBlock({'m', '3', 's', 'S'});
    enc->addBlock({'@', 'g', '{'});
    enc->finalise();

    out.flush();
    delete enc;

    try {

        // decrypt message
        std::stringstream in(out.str());
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(in, recipient_secretkey);
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Failed to find matching recipient.");
    }
}

TEST(encryption, failure_message) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    saltpack::MessageWriter *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
    enc->addBlock({'A', ' ', 'm', '3', 's', 'S', '@', 'g', '{'});
    enc->finalise();

    out.flush();
    delete enc;

    try {

        // decrypt message
        std::string mmsg = out.str();
        mmsg[mmsg.size() - 80] = (char)((int)mmsg[mmsg.size() - 80] + 1);
        std::stringstream in(mmsg);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(in, recipient_secretkey);
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Invalid authenticator.");
    }
}

TEST(encryption, armor) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(sender_publickey);
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;
    saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
    saltpack::MessageWriter *enc = new saltpack::MessageWriter(aOut, sender_secretkey, recipients, false);
    enc->addBlock({'A', 'n', 'o', 't', 'h', 'e', 'r', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'});
    enc->finalise();
    aOut.finalise();

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(is, recipient_secretkey);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }
    delete dec;

    ASSERT_EQ(msg.str(), "Another message");
}
