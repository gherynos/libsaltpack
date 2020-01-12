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

#include <regex>
#include "saltpack/ArmoredOutputStream.h"
#include "saltpack/Utils.h"
#include "saltpack/modes.h"
#include "saltpack/SaltpackException.h"
#include "saltpack/alphabets.h"

namespace saltpack {

    const std::regex APP_REGEXP("[a-zA-Z0-9]+");

    ArmoredOutputStream::ArmoredOutputStream(std::ostream &out, const std::string& app, int mode, int lettersInWords,
                                             int wordsInPhrase) : std::ostream(this), output(out) {

        if (!app.empty()) {

            std::smatch baseMatch;
            if (!std::regex_match(app, baseMatch, APP_REGEXP))
                throw SaltpackException("Wrong application name.");

            this->app = app;
        }

        this->mode = mode;
        this->lettersInWord = (size_t) lettersInWords;
        this->wordsInPhrase = (size_t) wordsInPhrase;
        buffer = BYTE_ARRAY(32);
        count = 0;
        lCount = (size_t) lettersInWords;
        wCount = 0;

        // write header
        output << "BEGIN ";
        if (!app.empty())
            output << app << " ";
        output << "SALTPACK ";
        switch (mode) {

            case MODE_ENCRYPTION: {

                output << "ENCRYPTED MESSAGE";
            }
                break;

            case MODE_ATTACHED_SIGNATURE: {

                output << "SIGNED MESSAGE";
            }
                break;

            case MODE_DETACHED_SIGNATURE: {

                output << "DETACHED SIGNATURE";
            }
                break;

            default:
                throw SaltpackException("Wrong mode.");
        }
        output << ". ";
    }

    ArmoredOutputStream::ArmoredOutputStream(std::ostream &out, const std::string& app, int mode) : ArmoredOutputStream(out,
                                                                                                                 app,
                                                                                                                 mode,
                                                                                                                 15,
                                                                                                                 200) {}

    ArmoredOutputStream::ArmoredOutputStream(std::ostream &out, int mode) : ArmoredOutputStream(out, "", mode, 15,
                                                                                                200) {}

    ArmoredOutputStream::ArmoredOutputStream(std::ostream &out, int mode, int lettersInWords, int wordsInPhrase)
            : ArmoredOutputStream(out, "", mode, lettersInWords, wordsInPhrase) {}

    ArmoredOutputStream::~ArmoredOutputStream() {

        buffer.clear();
        buffer.shrink_to_fit();
    }

    void ArmoredOutputStream::finalise() {

        if (count > 0) {

            writeToOutput(Utils::baseXencode(buffer, count, BASE62));
            count = 0;
        }

        // write footer
        output << ". END ";
        if (!app.empty())
            output << app << " ";
        output << "SALTPACK ";
        switch (mode) {

            case MODE_ENCRYPTION: {

                output << "ENCRYPTED MESSAGE";
            }
                break;

            case MODE_ATTACHED_SIGNATURE: {

                output << "SIGNED MESSAGE";
            }
                break;

            case MODE_DETACHED_SIGNATURE: {

                output << "DETACHED SIGNATURE";
            }
                break;

            default:
                throw SaltpackException("Wrong mode.");
        }
        output << ".";
    }

    int ArmoredOutputStream::overflow(int c) {

        if (count < 32) {

            buffer[count] = (BYTE) c;
            count += 1;

        } else {

            writeToOutput(Utils::baseXencode(buffer, count, BASE62));
            buffer[0] = (BYTE) c;
            count = 1;
        }

        return c;
    }

    void ArmoredOutputStream::writeToOutput(const std::string& data) {

        for (char i : data) {

            if (lCount == 0) {

                lCount = lettersInWord;
                if (++wCount == wordsInPhrase) {

                    wCount = 0;
                    output << "\r\n";

                } else
                    output << " ";
            }

            output << i;
            lCount--;
        }
    }
}
