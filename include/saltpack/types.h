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

#ifndef SALTPACK_TYPES_H
#define SALTPACK_TYPES_H

#include <iostream>
#include <vector>

/**
 * @brief The saltpack library namespace.
 */
namespace saltpack {

    typedef unsigned char BYTE; /**< An octet. */

    typedef std::vector<BYTE> BYTE_ARRAY; /**< An array of bytes. */
}

#endif //SALTPACK_TYPES_H
