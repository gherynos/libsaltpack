/*
 * Copyright 2017 Luca Zanconato
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

#ifndef SALTPACK_PAYLOADPACKETV2_H
#define SALTPACK_PAYLOADPACKETV2_H

#include <msgpack.hpp>
#include "PayloadPacket.h"

namespace saltpack {

    struct PayloadPacketV2 : PayloadPacket {

        bool finalFlag;
    };
}

namespace msgpack {

    MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {

        namespace adaptor {

            template<>
            struct convert<saltpack::PayloadPacketV2> {

                msgpack::object const &operator()(msgpack::object const &o, saltpack::PayloadPacketV2 &v) const {

                    if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
                    if (o.via.array.size != 3) throw msgpack::type_error();

                    v = saltpack::PayloadPacketV2();
                    v.finalFlag = o.via.array.ptr[0].as<bool>();
                    v.authenticatorsList = o.via.array.ptr[1].as<std::vector<saltpack::BYTE_ARRAY>>();
                    v.payloadSecretbox = o.via.array.ptr[2].as<saltpack::BYTE_ARRAY>();

                    return o;
                }
            };

            template<>
            struct pack<saltpack::PayloadPacketV2> {

                template<typename Stream>
                packer <Stream> &operator()(msgpack::packer<Stream> &o, saltpack::PayloadPacketV2 const &v) const {

                    o.pack_array(3);
                    o.pack(v.finalFlag);
                    o.pack(v.authenticatorsList);
                    o.pack(v.payloadSecretbox);

                    return o;
                }
            };
        }
    }
}

#endif //SALTPACK_PAYLOADPACKETV2_H
