libsaltpack
===========
A C++ implementation of [saltpack](https://saltpack.org).

Dependencies
------------

* [libsodium](https://download.libsodium.org/doc/) >= 1.0.3
* [msgpack](https://github.com/msgpack/msgpack-c) >= 2.0.0
* [GMP](https://gmplib.org/) >= 6.0.0 (or [MPIR](http://mpir.org/) >= 2.6.0 on Windows)

Building
--------

Here's how to build the static library on Linux or OSX:

```bash
cmake .
make
make test
make install
```

The library compiles under Windows (tested using CMake 3.6.2 and Visual Studio Community 2015).

Android Native Development Kit is also supported; see [libsaltpack-jni](https://github.com/Gherynos/libsaltpack-jni).

Documentation
-------------

The classes documentation can be found here: [https://gherynos.github.io/libsaltpack/annotated.html](https://gherynos.github.io/libsaltpack/annotated.html).

Examples
--------

### Encrypt/decrypt message

```c++
#include <saltpack.h>
#include <sodium.h>
#include <iostream>

int main(void) {

    try {
    
        // generate keypair
        saltpack::BYTE_ARRAY publickey(crypto_box_PUBLICKEYBYTES);
        saltpack::BYTE_ARRAY secretkey(crypto_box_SECRETKEYBYTES);
        saltpack::Utils::generateKeypair(publickey, secretkey);
        
        // recipients
        std::list<saltpack::BYTE_ARRAY> recipients;
        recipients.push_back(publickey);
        
        // encrypt message
        std::stringstream out;
        saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
        saltpack::MessageWriter *enc = new saltpack::MessageWriter(aOut, secretkey, recipients);
        enc->addBlock({'T', 'h', 'e', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'});
        enc->finalise();
        aOut.finalise();
        
        out.flush();
        delete enc;
        
        // display encrypted message
        std::cout << out.str() << std::endl;
    
        // decrypt message
        std::stringstream in(out.str());
        saltpack::ArmoredInputStream aIn(in);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(aIn, secretkey);
        while (dec->hasMoreBlocks()) {
        
            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;
        
        // display decrypted message
        std::cout << std::endl << msg.str() << std::endl;
    
    } catch (const saltpack::SaltpackException &ex) {
    
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }

    return 0;
}
```

### Sign/verify message

#### Attached signature

```c++
#include <saltpack.h>
#include <sodium.h>
#include <iostream>

int main(void) {

    try {
    
        // generate keypair
        saltpack::BYTE_ARRAY secretkey(crypto_sign_SECRETKEYBYTES);
        saltpack::BYTE_ARRAY publickey(crypto_sign_PUBLICKEYBYTES);
        saltpack::Utils::generateSignKeypair(publickey, secretkey);
        
        // sign message
        std::stringstream out;
        saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ATTACHED_SIGNATURE);
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, secretkey, false);
        sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'});
        sig->finalise();
        aOut.finalise();
        
        out.flush();
        delete sig;
        
        // display signed message
        std::cout << out.str() << std::endl;
        
        // verify message
        std::stringstream in(out.str());
        saltpack::ArmoredInputStream aIn(in);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(aIn);
        while (dec->hasMoreBlocks()) {
        
            saltpack::BYTE_ARRAY message = dec->getBlock();
            msg.write(reinterpret_cast<const char *>(message.data()), message.size());
        }
        delete dec;
    
        // display verified message
        std::cout << std::endl << msg.str() << std::endl;
    
    } catch (const saltpack::SaltpackException &ex) {
    
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }

    return 0;
}
```

#### Detached signature

```c++
#include <saltpack.h>
#include <sodium.h>
#include <iostream>

int main(void) {

    try {
    
        // generate keypair
        saltpack::BYTE_ARRAY secretkey(crypto_sign_SECRETKEYBYTES);
        saltpack::BYTE_ARRAY publickey(crypto_sign_PUBLICKEYBYTES);
        saltpack::Utils::generateSignKeypair(publickey, secretkey);
        
        // sign message
        std::stringstream out;
        saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_DETACHED_SIGNATURE);
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(aOut, secretkey, true);
        sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'});
        sig->finalise();
        aOut.finalise();
        
        out.flush();
        delete sig;
        
        // display signature
        std::cout << out.str() << std::endl;
        
        // verify message
        std::stringstream in(out.str());
        saltpack::ArmoredInputStream aIn(in);
        std::stringstream msg("a signed message");
        saltpack::MessageReader *dec = new saltpack::MessageReader(aIn, msg);
        delete dec;
    
    } catch (const saltpack::SaltpackException &ex) {
    
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }

    return 0;
}
```

Copyright and license
---------------------

Copyright 2016-2017 Luca Zanconato (<luca.zanconato@nharyes.net>)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this work except in compliance with the License.
You may obtain a copy of the License in the LICENSE file, or at:

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.