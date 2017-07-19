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

TEST(armor, enc) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, saltpack::MODE_ENCRYPTION);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    std::stringstream input(step.str());
    saltpack::ArmoredInputStream *aIn = new saltpack::ArmoredInputStream(input);

    char buffer[12];
    std::stringstream coll;
    while (!aIn->eof()) {

        aIn->read(buffer, 12);
        coll.write(buffer, aIn->gcount());
    }
    delete aIn;

    std::string s = coll.str();
    saltpack::BYTE_ARRAY cmp(s.size());
    for (unsigned int i = 0; i < s.size(); i++)
        cmp[i] = (saltpack::BYTE) s[i];

    ASSERT_EQ(data, cmp);
}

TEST(armor, att) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, saltpack::MODE_ATTACHED_SIGNATURE);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    std::stringstream input(step.str());
    saltpack::ArmoredInputStream *aIn = new saltpack::ArmoredInputStream(input);

    char buffer[12];
    std::stringstream coll;
    while (!aIn->eof()) {

        aIn->read(buffer, 12);
        coll.write(buffer, aIn->gcount());
    }
    delete aIn;

    std::string s = coll.str();
    saltpack::BYTE_ARRAY cmp(s.size());
    for (unsigned int i = 0; i < s.size(); i++)
        cmp[i] = (saltpack::BYTE) s[i];

    ASSERT_EQ(data, cmp);
}

TEST(armor, det) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, saltpack::MODE_DETACHED_SIGNATURE);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    std::stringstream input(step.str());
    saltpack::ArmoredInputStream *aIn = new saltpack::ArmoredInputStream(input);

    char buffer[12];
    std::stringstream coll;
    while (!aIn->eof()) {

        aIn->read(buffer, 12);
        coll.write(buffer, aIn->gcount());
    }
    delete aIn;

    std::string s = coll.str();
    saltpack::BYTE_ARRAY cmp(s.size());
    for (unsigned int i = 0; i < s.size(); i++)
        cmp[i] = (saltpack::BYTE) s[i];

    ASSERT_EQ(data, cmp);
}

TEST(armor, enc_rnd) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, "MYAPP", saltpack::MODE_ENCRYPTION,
                                                                            rand() % 10 + 1, rand() % 100 + 1);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    std::stringstream input(step.str());
    saltpack::ArmoredInputStream *aIn = new saltpack::ArmoredInputStream(input, "MYAPP");

    char buffer[12];
    std::stringstream coll;
    while (!aIn->eof()) {

        aIn->read(buffer, 12);
        coll.write(buffer, aIn->gcount());
    }
    delete aIn;

    std::string s = coll.str();
    saltpack::BYTE_ARRAY cmp(s.size());
    for (unsigned int i = 0; i < s.size(); i++)
        cmp[i] = (saltpack::BYTE) s[i];

    ASSERT_EQ(data, cmp);
}

TEST(armor, att_rnd) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, saltpack::MODE_ATTACHED_SIGNATURE,
                                                                            rand() % 10 + 1, rand() % 100 + 1);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    std::stringstream input(step.str());
    saltpack::ArmoredInputStream *aIn = new saltpack::ArmoredInputStream(input);

    char buffer[12];
    std::stringstream coll;
    while (!aIn->eof()) {

        aIn->read(buffer, 12);
        coll.write(buffer, aIn->gcount());
    }
    delete aIn;

    std::string s = coll.str();
    saltpack::BYTE_ARRAY cmp(s.size());
    for (unsigned int i = 0; i < s.size(); i++)
        cmp[i] = (saltpack::BYTE) s[i];

    ASSERT_EQ(data, cmp);
}

TEST(armor, det_rnd) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, saltpack::MODE_DETACHED_SIGNATURE,
                                                                            rand() % 10 + 1, rand() % 100 + 1);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    std::stringstream input(step.str());
    saltpack::ArmoredInputStream *aIn = new saltpack::ArmoredInputStream(input);

    char buffer[12];
    std::stringstream coll;
    while (!aIn->eof()) {

        aIn->read(buffer, 12);
        coll.write(buffer, aIn->gcount());
    }
    delete aIn;

    std::string s = coll.str();
    saltpack::BYTE_ARRAY cmp(s.size());
    for (unsigned int i = 0; i < s.size(); i++)
        cmp[i] = (saltpack::BYTE) s[i];

    ASSERT_EQ(data, cmp);
}

TEST(armor, wrong_app) {

    saltpack::BYTE_ARRAY data((unsigned long) (rand() % 1000 + 1));
    randombytes_buf(data.data(), data.size());

    std::stringstream step;
    saltpack::ArmoredOutputStream *aOut = new saltpack::ArmoredOutputStream(step, "App1",
                                                                            saltpack::MODE_DETACHED_SIGNATURE,
                                                                            rand() % 10 + 1, rand() % 100 + 1);
    aOut->write((const char *) data.data(), data.size());
    aOut->finalise();

    delete aOut;

    try {

        std::stringstream input(step.str());
        saltpack::ArmoredInputStream aIn(input, "App2");

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Wrong application.");
    }
}

TEST(armor, wrong_app_name) {

    try {

        std::stringstream step;
        saltpack::ArmoredOutputStream aOut(step, "a name", saltpack::MODE_DETACHED_SIGNATURE);

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Wrong application name.");
    }

    try {

        std::stringstream input;
        saltpack::ArmoredInputStream aIn(input, "an.app");

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Wrong application name.");
    }
}

TEST(armor, wrong_header_footer) {

    try {

        std::string message = "BEGIN SOLTPACK ENCRYPTED MESSAGE. 0c83np9BDvp5DXP 26S70I. END SALTPACK ENCRYPTED MESSAGE.";

        std::stringstream input(message);
        saltpack::ArmoredInputStream aIn(input);

        throw std::bad_exception();

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Wrong header.");
    }

    std::string message = "BEGIN SALTPACK ENCRYPTED MESSAGE. 0c83np9BDvp5DXP 26S70I. END SALTPACK ENCRYPTOD MESSAGE.";

    std::stringstream input(message);
    saltpack::ArmoredInputStream aIn(input);

    char buffer[12];
    std::stringstream coll;
    while (!aIn.eof()) {

        aIn.read(buffer, 12);
        coll.write(buffer, aIn.gcount());
    }

    ASSERT_EQ(coll.str().size(), 0);
}

TEST(armor, wrong_mode) {

    try {

        std::stringstream step;
        saltpack::ArmoredOutputStream aOut(step, saltpack::MODE_SIGNCRYPTION);

    } catch (const saltpack::SaltpackException ex) {

        ASSERT_STREQ(ex.what(), "Wrong mode.");
    }
}
