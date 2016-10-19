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

#ifndef SALTPACK_ARMOREDOUTPUTSTREAM_H
#define SALTPACK_ARMOREDOUTPUTSTREAM_H

#include <iostream>
#include "types.h"

namespace saltpack {

    class ArmoredOutputStream : public std::ostream, std::streambuf {

    public:
        ArmoredOutputStream(std::ostream &out, std::string app, int mode, int lettersInWords, int wordsInPhrase);

        ArmoredOutputStream(std::ostream &out, std::string app, int mode);

        ArmoredOutputStream(std::ostream &out, int mode, int lettersInWords, int wordsInPhrase);

        ArmoredOutputStream(std::ostream &out, int mode);

        virtual ~ArmoredOutputStream();

        virtual int overflow(int __c) override;

        void finalise();

    private:
        std::ostream &output;
        std::string app;
        int mode;
        BYTE_ARRAY buffer;
        size_t count;

        size_t lettersInWord;
        size_t wordsInPhrase;
        size_t lCount;
        size_t wCount;

        void writeToOutput(std::string data);
    };
}

#endif //SALTPACK_ARMOREDOUTPUTSTREAM_H
