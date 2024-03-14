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

#ifndef SALTPACK_SALTPACKEXCEPTION_H
#define SALTPACK_SALTPACKEXCEPTION_H

#include <iostream>

namespace saltpack {

    /**
     *  @brief Saltpack exception.
     */
    class SaltpackException : public std::exception {
        std::runtime_error m;

    public:
        explicit SaltpackException(const std::string &msg) : m(msg.c_str()) {}

        ~SaltpackException() noexcept override = default;

        const char *what() const noexcept override {
            return m.what();
        }
    };

    static_assert(std::is_nothrow_copy_constructible<SaltpackException>::value,
                  "SaltpackException must be nothrow copy constructible");
}

#endif //SALTPACK_SALTPACKEXCEPTION_H
