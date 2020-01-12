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

#ifndef SALTPACK_HEADERPACKET_H
#define SALTPACK_HEADERPACKET_H

#include <msgpack.hpp>
#include "HeaderPacketRecipient.h"

namespace saltpack {

    struct HeaderPacket {

        std::string format;
        std::vector<int> version;
        int mode;
        BYTE_ARRAY ephemeralPublicKey;
        BYTE_ARRAY senderSecretbox;
        std::vector<HeaderPacketRecipient> recipientsList;
    };
}

namespace msgpack {

    MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {

        namespace adaptor {

            template<>
            struct convert<saltpack::HeaderPacket> {

                msgpack::object const &operator()(msgpack::object const &o, saltpack::HeaderPacket &v) const {

                    if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
                    if (o.via.array.size != 6) throw msgpack::type_error();

                    v = saltpack::HeaderPacket();
                    v.format = o.via.array.ptr[0].as<std::string>();
                    v.version = o.via.array.ptr[1].as<std::vector<int>>();
                    v.mode = o.via.array.ptr[2].as<int>();
                    v.ephemeralPublicKey = o.via.array.ptr[3].as<saltpack::BYTE_ARRAY>();
                    v.senderSecretbox = o.via.array.ptr[4].as<saltpack::BYTE_ARRAY>();
                    v.recipientsList = o.via.array.ptr[5].as<std::vector<saltpack::HeaderPacketRecipient>>();

                    return o;
                }
            };

            template<>
            struct pack<saltpack::HeaderPacket> {

                template<typename Stream>
                packer<Stream> &operator()(msgpack::packer<Stream> &o, saltpack::HeaderPacket const &v) const {

                    o.pack_array(6);
                    o.pack(v.format);
                    if (v.version.size() != 2) throw msgpack::type_error();
                    o.pack(v.version);
                    o.pack(v.mode);
                    o.pack(v.ephemeralPublicKey);
                    o.pack(v.senderSecretbox);
                    o.pack(v.recipientsList);

                    return o;
                }
            };
        }
    }
}

#endif //SALTPACK_HEADERPACKET_H
