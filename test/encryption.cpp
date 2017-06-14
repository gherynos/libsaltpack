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
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '{'}, true);

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

    for (saltpack::BYTE_ARRAY rec: dec->getRecipients())
        ASSERT_EQ(rec.size(), (unsigned long) 0);

    ASSERT_EQ(sender_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());

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
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '{'}, true);

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
    enc->addBlock({'A', ' ', 'm', '3', 's', 'S', '@', 'g', '{'}, false);
    enc->addBlock({}, true);

    out.flush();
    delete enc;

    try {

        // decrypt message
        std::string mmsg = out.str();
        mmsg[mmsg.size() - 80] = (char) ((int) mmsg[mmsg.size() - 80] + 1);
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
    saltpack::MessageWriter *enc = new saltpack::MessageWriter(aOut, sender_secretkey, recipients);
    enc->addBlock({'A', 'n', 'o', 't', 'h', 'e', 'r', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
    aOut.finalise();

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(is, recipient_secretkey);
    ASSERT_EQ(recipients, dec->getRecipients());
    ASSERT_EQ(sender_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }
    delete dec;

    ASSERT_EQ(msg.str(), "Another message");
}

TEST(encryption, intentionally_anonymous) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    saltpack::MessageWriter *enc = new saltpack::MessageWriter(out, recipients, false);
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '!'}, true);

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

    for (saltpack::BYTE_ARRAY rec: dec->getRecipients())
        ASSERT_EQ(rec.size(), (unsigned long) 0);

    ASSERT_TRUE(dec->isIntentionallyAnonymous());

    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g!");
}

TEST(encryption, intentionally_anonymous_rec) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    saltpack::MessageWriter *enc = new saltpack::MessageWriter(out, recipients);
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '!'}, false);
    enc->addBlock({'?'}, true);

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

    ASSERT_TRUE(dec->isIntentionallyAnonymous());

    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g!?");
}

TEST(encryption, final_block) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    try {

        saltpack::MessageWriter *enc = new saltpack::MessageWriter(out, recipients);
        enc->addBlock({'B', 'l'}, false);
        enc->addBlock({'a', ' ', 'b', 'l'}, true);
        enc->addBlock({'a', '.', '.', '.'}, true);

        out.flush();
        delete enc;

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Final block already added.");
    }
}

TEST(encryption, message_truncated) {

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
    enc->addBlock({'A', ' ', 'm', '3', 's', 'S', '@', 'g', '{'}, false);

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

        ASSERT_STREQ(ex.what(), "Not enough data found to decode block (message truncated?).");
    }
}

TEST(encryption, version_one) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned long i = 0; i < recipient_secretkey.size(); i++)
        recipient_secretkey[i] = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    std::string ciphertext = "BEGIN SALTPACK ENCRYPTED MESSAGE. kcJn5brvybfNjz6 D5litY0cgUolWnj 1wQIat4Gid1knpi "
            "50BRnYVJRpu95Bz T1i84DU9kSb7nf2 HIGFqpKidQhpi1s rueA1oCetAEY1fS 1sxevL8ofX5JCbZ DAhVmFBZUw5CQgy "
            "HVmPY4Ajs69of5i SvHhfaQZrCF1Mte nKBWuZWa24hJJcH nE0azeltYMlMjt8 BFfKvw11g7U7CA6 OKYcjRHos7mi1qz "
            "LIb5inzi8GD4lKG nGAOv6Crg3DaAqh DFUdt6qs4bLsoXM 7TMdgANStFooqrH QuZBeLyDgLIHrTR htxbVoWWffXYH1H "
            "kdxDF2aGiowq7fb Jht3PgjfwDeldT2 HW498MnbHt7KBsS rcO8rhmkbfROMhg haoqoJ. END SALTPACK ENCRYPTED MESSAGE.";

    // decrypt message
    std::stringstream in(ciphertext);
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    saltpack::MessageReader *dec = new saltpack::MessageReader(is, recipient_secretkey);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    delete dec;

    ASSERT_EQ(msg.str(), "A very secr3t M3ss4ge\n");
}
