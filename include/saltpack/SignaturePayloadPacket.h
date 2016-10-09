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

#ifndef SALTPACK_SIGNATUREPAYLOADPACKET_H
#define SALTPACK_SIGNATUREPAYLOADPACKET_H

#include <msgpack.hpp>

namespace saltpack {

    struct SignaturePayloadPacket {

        BYTE_ARRAY signature;
        BYTE_ARRAY payloadChunk;
    };
}

namespace msgpack {

    MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {

        namespace adaptor {

            template<>
            struct convert<saltpack::SignaturePayloadPacket> {

                msgpack::object const &operator()(msgpack::object const &o, saltpack::SignaturePayloadPacket &v) const {

                    if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
                    if (o.via.array.size != 2) throw msgpack::type_error();

                    v = saltpack::SignaturePayloadPacket();
                    v.signature = o.via.array.ptr[0].as<saltpack::BYTE_ARRAY>();
                    v.payloadChunk = o.via.array.ptr[1].as<saltpack::BYTE_ARRAY>();

                    return o;
                }
            };

            template<>
            struct pack<saltpack::SignaturePayloadPacket> {

                template<typename Stream>
                packer <Stream> &
                operator()(msgpack::packer<Stream> &o, saltpack::SignaturePayloadPacket const &v) const {

                    o.pack_array(2);
                    o.pack(v.signature);
                    o.pack(v.payloadChunk);

                    return o;
                }
            };
        }
    }
}

#endif //SALTPACK_SIGNATUREPAYLOADPACKET_H
