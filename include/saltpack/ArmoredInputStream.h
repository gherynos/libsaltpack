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

#ifndef SALTPACK_ARMOREDINPUTSTREAM_H
#define SALTPACK_ARMOREDINPUTSTREAM_H

#include <iostream>
#include <sstream>
#include "types.h"

namespace saltpack {

    /**
     * @brief Input Stream to parse BaseX armored content.
     *
     *  The alphabet used is BASE62.
     */
    class ArmoredInputStream : public std::istream, std::streambuf {

    public:
        /**
         * Creates a new ArmoredInputStream instance for a specific application.
         *
         * @param in the source input stream containing armored data.
         * @param app the application name that will be verified in the header/footer of the message contained
         * in the input stream.
         *
         * @throws SaltpackException
         */
        ArmoredInputStream(std::istream &in, const std::string& app);

        /**
         * Creates a new ArmoredInputStream instance.
         *
         * @param in the source input stream containing armored data.
         *
         * @throws SaltpackException
         */
        explicit ArmoredInputStream(std::istream &in);

        /**
         * Destroyer.
         */
        ~ArmoredInputStream() override;

        /**
         * Method overridden from std::sreambuf (internal use only).
         *
         * @return the next available character.
         */
        int underflow() override;

    private:
        char ch{};
        std::string app;
        std::istream &input;
        std::stringstream buffer;
        BYTE_ARRAY dataBuffer;
        size_t index;
        bool dataReady;
        bool footerReached;
        bool footerVerified;
        std::string mode;
    };
}

#endif //SALTPACK_ARMOREDINPUTSTREAM_H
