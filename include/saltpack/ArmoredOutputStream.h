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

#ifndef SALTPACK_ARMOREDOUTPUTSTREAM_H
#define SALTPACK_ARMOREDOUTPUTSTREAM_H

#include <iostream>
#include "types.h"

namespace saltpack {

    /**
     *  @brief Output Stream to generate BaseX armored content.
     *
     *  The alphabet used is BASE62.
     */
    class ArmoredOutputStream : public std::ostream, std::streambuf {

    public:
        /**
         * Creates a new ArmoredInputStream instance for a specific application.
         *
         * @param out the destination output stream.
         * @param app the application name that will be added to the header/footer of the message.
         * @param mode the message mode, either saltpack::MODE_ENCRYPTION, saltpack::MODE_ATTACHED_SIGNATURE
         * or saltpack::MODE_DETACHED_SIGNATURE.
         * @param lettersInWords the number of letters before producing a space during the armoring.
         * @param wordsInPhrase the number of words before producing a new line during the armoring.
         *
         * @throws SaltpackException
         */
        ArmoredOutputStream(std::ostream &out, const std::string& app, int mode, int lettersInWords, int wordsInPhrase);

        /**
         * Creates a new ArmoredInputStream instance for a specific application.
         * This instance will produce a space every 15 letters and a new line after 200 words.
         *
         * @param out the destination output stream.
         * @param app the application name that will be added to the header/footer of the message.
         * @param mode the message mode, either saltpack::MODE_ENCRYPTION, saltpack::MODE_ATTACHED_SIGNATURE or
         * saltpack::MODE_DETACHED_SIGNATURE.
         *
         * @throws SaltpackException
         */
        ArmoredOutputStream(std::ostream &out, const std::string& app, int mode);

        /**
         * Creates a new ArmoredInputStream instance.
         *
         * @param out the destination output stream.
         * @param mode the message mode, either saltpack::MODE_ENCRYPTION, saltpack::MODE_ATTACHED_SIGNATURE or
         * saltpack::MODE_DETACHED_SIGNATURE.
         * @param lettersInWords the number of letters before producing a space during the armoring.
         * @param wordsInPhrase the number of words before producing a new line during the armoring.
         *
         * @throws SaltpackException
         */
        ArmoredOutputStream(std::ostream &out, int mode, int lettersInWords, int wordsInPhrase);

        /**
         * Creates a new ArmoredInputStream instance.
         * This instance will produce a space every 15 letters and a new line after 200 words.
         *
         * @param out the destination output stream.
         * @param mode the message mode, either saltpack::MODE_ENCRYPTION, saltpack::MODE_ATTACHED_SIGNATURE or
         * saltpack::MODE_DETACHED_SIGNATURE.
         *
         * @throws SaltpackException
         */
        ArmoredOutputStream(std::ostream &out, int mode);

        /**
         * Destructor.
         */
        ~ArmoredOutputStream() override;

        /**
         * Method overridden from std::streambuf (internal use only).
         *
         * @param __c the next character to output.
         */
        int overflow(int __c) override;

        /**
         * Finalises the stream. This method must be called when after MessageWriter#finalise() in order to
         * flush the remaining characters and produce the footer.
         *
         * @throws SaltpackException
         */
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

        void writeToOutput(const std::string& data);
    };
}

#endif //SALTPACK_ARMOREDOUTPUTSTREAM_H
