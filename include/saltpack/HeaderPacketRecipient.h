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

#ifndef SALTPACK_HEADERPACKETRECIPIENT_H
#define SALTPACK_HEADERPACKETRECIPIENT_H

#include "types.h"
#include <msgpack.hpp>

namespace saltpack {

    struct HeaderPacketRecipient {

        BYTE_ARRAY recipientPublicKey;  // if empty, will be serialised to NULL and vice-versa
        BYTE_ARRAY payloadKeyBox;
    };
}

namespace msgpack {

    MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {

        namespace adaptor {

            template<>
            struct convert<saltpack::HeaderPacketRecipient> {

                msgpack::object const &operator()(msgpack::object const &o, saltpack::HeaderPacketRecipient &v) const {

                    if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
                    if (o.via.array.size != 2) throw msgpack::type_error();

                    v = saltpack::HeaderPacketRecipient();
                    if (!o.via.array.ptr[0].is_nil())
                        v.recipientPublicKey = o.via.array.ptr[0].as<saltpack::BYTE_ARRAY>();
                    v.payloadKeyBox = o.via.array.ptr[1].as<saltpack::BYTE_ARRAY>();

                    return o;
                }
            };

            template<>
            struct pack<saltpack::HeaderPacketRecipient> {

                template<typename Stream>
                packer <Stream> &
                operator()(msgpack::packer<Stream> &o, saltpack::HeaderPacketRecipient const &v) const {

                    o.pack_array(2);
                    if (!v.recipientPublicKey.empty())
                        o.pack(v.recipientPublicKey);
                    else
                        o.pack_nil();
                    o.pack(v.payloadKeyBox);

                    return o;
                }
            };
        }
    }
}

#endif //SALTPACK_HEADERPACKETRECIPIENT_H
