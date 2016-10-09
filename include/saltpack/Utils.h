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

#ifndef SALTPACK_UTILS_H
#define SALTPACK_UTILS_H

#include "types.h"

namespace saltpack {

    class Utils {

    public:
        static void generateKeypair(BYTE_ARRAY &publickey, BYTE_ARRAY &secretkey);

        static void generateSignKeypair(BYTE_ARRAY &publickey, BYTE_ARRAY &secretkey);

        static BYTE_ARRAY derivePublickey(BYTE_ARRAY secretkey);

        static int baseXblockSize(std::string alphabet, int size);

        static std::string baseXencode(BYTE_ARRAY data, std::string alphabet);

        static std::string baseXencode(BYTE_ARRAY data, size_t size, std::string alphabet);

        static BYTE_ARRAY baseXdecode(std::string data, std::string alphabet);

        static BYTE_ARRAY hexToBin(std::string hex);

        static std::string binToHex(BYTE_ARRAY bin);
    };
}

#endif //SALTPACK_UTILS_H
