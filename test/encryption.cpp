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

#include <gtest/gtest.h>
#include <fstream>
#include <saltpack.h>
#include <sodium.h>

TEST(encryption, main) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
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

    auto *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '{'}, true);

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    std::stringstream msg;
    auto *dec = new saltpack::MessageReader(in, recipient_secretkey);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    for (const saltpack::BYTE_ARRAY& rec: dec->getRecipients())
        ASSERT_EQ(rec.size(), (unsigned long) 0);

    ASSERT_EQ(sender_publickey, dec->getSender());
    ASSERT_FALSE(dec->isIntentionallyAnonymous());

    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g{");
}

TEST(encryption, failure_recipient) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(sender_publickey);

    // encrypt message
    std::stringstream out;

    auto *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '{'}, true);

    out.flush();
    delete enc;

    try {

        // decrypt message
        std::stringstream in(out.str());
        std::stringstream msg;
        auto *dec = new saltpack::MessageReader(in, recipient_secretkey);
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

        ASSERT_STREQ(ex.what(), "Failed to find matching recipient.");
    }
}

TEST(encryption, failure_message) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    auto *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
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
        auto *dec = new saltpack::MessageReader(in, recipient_secretkey);
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

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
    auto *enc = new saltpack::MessageWriter(aOut, sender_secretkey, recipients);
    enc->addBlock({'A', 'n', 'o', 't', 'h', 'e', 'r', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
    aOut.finalise();

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    saltpack::ArmoredInputStream is(in);
    std::stringstream msg;
    auto *dec = new saltpack::MessageReader(is, recipient_secretkey);
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
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    auto *enc = new saltpack::MessageWriter(out, recipients, false);
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '!'}, true);

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    std::stringstream msg;
    auto *dec = new saltpack::MessageReader(in, recipient_secretkey);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    for (const saltpack::BYTE_ARRAY& rec: dec->getRecipients())
        ASSERT_EQ(rec.size(), (unsigned long) 0);

    ASSERT_TRUE(dec->isIntentionallyAnonymous());

    delete dec;

    ASSERT_EQ(msg.str(), "A m3sS@g!");
}

TEST(encryption, intentionally_anonymous_rec) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    auto *enc = new saltpack::MessageWriter(out, recipients);
    enc->addBlock({'A', ' '}, false);
    enc->addBlock({'m', '3', 's', 'S'}, false);
    enc->addBlock({'@', 'g', '!'}, false);
    enc->addBlock({'?'}, true);

    out.flush();
    delete enc;

    // decrypt message
    std::stringstream in(out.str());
    std::stringstream msg;
    auto *dec = new saltpack::MessageReader(in, recipient_secretkey);
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
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    try {

        auto *enc = new saltpack::MessageWriter(out, recipients);
        enc->addBlock({'B', 'l'}, false);
        enc->addBlock({'a', ' ', 'b', 'l'}, true);
        enc->addBlock({'a', '.', '.', '.'}, true);

        out.flush();
        delete enc;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

        ASSERT_STREQ(ex.what(), "Final block already added.");
    }
}

TEST(encryption, message_truncated) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
    saltpack::BYTE_ARRAY recipient_publickey = saltpack::Utils::derivePublickey(recipient_secretkey);

    saltpack::BYTE_ARRAY sender_publickey(crypto_box_PUBLICKEYBYTES);
    saltpack::BYTE_ARRAY sender_secretkey(crypto_box_SECRETKEYBYTES);
    saltpack::Utils::generateKeypair(sender_publickey, sender_secretkey);

    // recipients
    std::list<saltpack::BYTE_ARRAY> recipients;
    recipients.push_back(recipient_publickey);

    // encrypt message
    std::stringstream out;

    auto *enc = new saltpack::MessageWriter(out, sender_secretkey, recipients, false);
    enc->addBlock({'A', ' ', 'm', '3', 's', 'S', '@', 'g', '{'}, false);

    out.flush();
    delete enc;

    try {

        // decrypt message
        std::stringstream in(out.str());
        std::stringstream msg;
        auto *dec = new saltpack::MessageReader(in, recipient_secretkey);
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

        ASSERT_STREQ(ex.what(), "Not enough data found to decode block (message truncated?).");
    }
}

TEST(encryption, version_one) {

    saltpack::BYTE_ARRAY recipient_secretkey(crypto_box_SECRETKEYBYTES);
    for (unsigned char & i : recipient_secretkey)
        i = (char) 0;
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
    auto *dec = new saltpack::MessageReader(is, recipient_secretkey);
    while (dec->hasMoreBlocks()) {

        saltpack::BYTE_ARRAY message = dec->getBlock();
        msg.write(reinterpret_cast<const char *>(message.data()), message.size());
    }

    delete dec;

    ASSERT_EQ(msg.str(), "A very secr3t M3ss4ge\n");
}

TEST(encryption, wrong_keys) {

    try {

        // decrypt message
        std::stringstream in("sample");
        std::stringstream msg;
        auto *dec = new saltpack::MessageReader(in, saltpack::BYTE_ARRAY(2));
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

        ASSERT_STREQ(ex.what(), "Wrong size for recipientSecretkey.");
    }
}

TEST(encryption, wrong_header) {

    try {

        // decrypt message
        std::stringstream in("BEGIN SALTPACK ENCRYPTED MESSAGE. kiNKSFgXTKGnAwu ubhuHbww2DhUarY yKvUp0710jrfxwc"
                                     "H6hmh19KDApnDiv 09J7XNoWAO6uIZH OrNQhZ9nLwiEBby VBLek3ityGlPnTT m6ZG6Rj6yAAc1Iq"
                                     "gUC0GVRspXC1GwP 0CUssB1UPfAvtfM 93LTEe2m3A4PHgk kBHCBWbMVZ2sZN8 k4KLYJqN4vJoyns"
                                     "5LkxnuZZxaDBdK4 GyUcSDkL9rUe9yd vHokVuLwvtStl3f OrueDSJJ1QsQWUG QKFsPzuBOktKN4u"
                                     "hAYHYlIodVZMkXc G2597rELzoqV0J4 GBY83zuSNOwhQLz nNqrUOoUBvQsU0I P0R2EBJeU12ImqI"
                                     "gMuojZ0FHyehrbz tqQ1VpxFf9GkHm3 Ze3R2YNFOT1MmJh BDwxj7gOLPpSwvl JTqzB7vJNGpgDYw"
                                     "gdgKtpZ3OXad5H9 EExXRfvqB3nlMr9 2gEnDApr2SdblML 7ADPUzz54GvhC7D qaY7cMuN1Dl1ebs"
                                     "WmmqIdlKO7Wy. END SALTPACK ENCRYPTED MESSAGE.");
        saltpack::ArmoredInputStream is(in);
        std::stringstream msg;
        auto *dec = new saltpack::MessageReader(is, saltpack::BYTE_ARRAY(crypto_box_SECRETKEYBYTES));
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

        ASSERT_STREQ(ex.what(), "Unrecognized format name: saltpack2.");
    }

    try {

        // decrypt message
        std::stringstream in("BEGIN SALTPACK ENCRYPTED MESSAGE. kiNJamlTJ29ZvW4 RHAOfdesqbrbMPT IEm20TfpjOhY6uK"
                                     "4sRe4HN10N6YGMU O7Le354q6i1V2Vz UMaYO3f7ghss5Ln CLwsW5IssiNX9U6 nMgnsCKNlheM0Fp"
                                     "3ObSbQQsFnrznSE FlFM9dqtK5oEGdw q584hAqAwArLEb7 8tB7e7frINSeyMW WDePDZNArUBOz6o"
                                     "TGFXvDBESIZL1ho enjxsihZfEw44rK aNDAJS0jo42HMCM XlZaodvTsqMSG86 eSjTn8jfey8UYwn"
                                     "3un3CaNr4ZD6eH3 gPv7WhCGbhfHho6 S0TVdnhgjjICMLT bFaOq7IOgsojXqp T8Iae9GJOb08iF3"
                                     "bbNjrzfkJdZLVYS 3PLnyeTVaCUMqvf 5G1b04Uo6k27QD9 0L2HMjwTt8pwWje zknYYXQS9iq1DzD"
                                     "uwjEuYKHvswaC7O 5B5QjqRRbJs5RNu gW2fK3obqFtzVq2 xbjeUKr91gzsiAq N6LaNWKjuKNhEX7"
                                     "TQYo5ZrW0Uf. END SALTPACK ENCRYPTED MESSAGE.");
        saltpack::ArmoredInputStream is(in);
        std::stringstream msg;
        auto *dec = new saltpack::MessageReader(is, saltpack::BYTE_ARRAY(crypto_box_SECRETKEYBYTES));
        while (dec->hasMoreBlocks()) {

            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException &ex) {

        ASSERT_STREQ(ex.what(), "Incompatible version: 1.1.");
    }
}
