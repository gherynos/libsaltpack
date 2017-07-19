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

#include <regex>
#include "saltpack/ArmoredInputStream.h"
#include "saltpack/Utils.h"
#include "saltpack/SaltpackException.h"
#include "saltpack/alphabets.h"

namespace saltpack {

    const std::regex HEADER_REGEXP(
            "[>\\n\\r\\t ]*BEGIN[>\\n\\r\\t ]+(?:([a-zA-Z0-9]+)[>\\n\\r\\t ]+)?SALTPACK[>\\n\\r\\t ]+((?:ENCRYPTED|SIGNED)[>\\n\\r\\t ]+MESSAGE|DETACHED[>\\n\\r\\t ]+SIGNATURE)");

    const std::regex FOOTER_REGEXP(
            "[>\\n\\r\\t ]*END[>\\n\\r\\t ]+(?:([a-zA-Z0-9]+)[>\\n\\r\\t ]+)?SALTPACK[>\\n\\r\\t ]+((?:ENCRYPTED|SIGNED)[>\\n\\r\\t ]+MESSAGE|DETACHED[>\\n\\r\\t ]+SIGNATURE)");

    const std::regex APP_REGEXP("[a-zA-Z0-9]+");

    const std::streampos BUFFER_SIZE = (std::streampos) Utils::baseXblockSize(BASE62, 32);

    const std::streampos ZERO = 0;

    ArmoredInputStream::ArmoredInputStream(std::istream &in, std::string app) : std::istream(this), input(in) {

        if (app != "") {

            std::smatch baseMatch;
            if (!std::regex_match(app, baseMatch, APP_REGEXP))
                throw SaltpackException("Wrong application name.");

            this->app = app;
        }

        index = 0;
        dataReady = false;
        footerReached = false;
        footerVerified = false;

        // read header
        char c;
        std::stringstream header;
        while (!input.eof()) {

            input.get(c);
            if (c == '.')
                break;
            header << c;
        }

        // check header
        std::smatch baseMatch;
        std::string sHeader = header.str();
        if (!std::regex_match(sHeader, baseMatch, HEADER_REGEXP))
            throw SaltpackException("Wrong header.");
        else
            mode = baseMatch[2];
        if (app != "" && baseMatch[1] != app)
            throw SaltpackException("Wrong application.");
    }

    ArmoredInputStream::ArmoredInputStream(std::istream &in) : ArmoredInputStream(in, "") {}

    ArmoredInputStream::~ArmoredInputStream() {

        dataBuffer.clear();
        dataBuffer.shrink_to_fit();
    }

    int ArmoredInputStream::underflow() {

        if (!dataReady && footerReached)
            return std::istream::traits_type::eof();

        // refill internal buffer with BaseX-decoded data
        std::stringstream footer;
        while (!dataReady && !input.eof()) {

            char c;
            while (!input.eof()) {

                // check buffer full
                if (buffer.tellp() == BUFFER_SIZE)
                    break;

                // read char
                input.get(c);
                if (input.gcount() == 0)
                    continue;

                // check char
                if (footerReached) {

                    if (c == '.')
                        break;
                    else
                        footer << c;

                } else if (c == '.') {

                    footerReached = true;

                } else if (c != ' ' && c != '>' && c != '\n' && c != '\r' && c != '\t')
                    buffer << c;
            }

            if (buffer.tellp() == ZERO && footerVerified)
                break;

            if (footerReached) {

                // check footer
                std::smatch base_match;
                std::string sFooter = footer.str();
                if (!std::regex_match(sFooter, base_match, FOOTER_REGEXP) || base_match[2] != mode ||
                    (app != "" && base_match[1] != app)) {

                    dataReady = false;
                    footerReached = true;
                    return std::istream::traits_type::eof();
                }

                footerVerified = true;
            }

            if (buffer.tellp() > ZERO) {

                // decode BaseX data
                dataBuffer = Utils::baseXdecode(buffer.str(), BASE62);

                // reset buffer
                buffer.str(std::string());
                buffer.clear();

                index = 0;
                dataReady = true;
            }
        }

        // output current char
        if (dataReady) {

            ch = dataBuffer[index];
            setg(&ch, &ch, &ch + 1);

        } else if (footerReached)
            return std::istream::traits_type::eof();

        // check for end of internal buffer
        if (++index == dataBuffer.size()) {

            dataReady = false;
            index = 0;
        }

        return std::istream::traits_type::to_int_type(*gptr());
    }
}
