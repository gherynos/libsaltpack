libsaltpack
===========
A C++ implementation of [saltpack](https://saltpack.org).

[![Build Status](https://github.com/gherynos/libsaltpack/workflows/build/badge.svg)](https://github.com/gherynos/libsaltpack/actions/workflows/build.yaml)
[![Coverage Status](https://coveralls.io/repos/github/gherynos/libsaltpack/badge.svg?branch=main)](https://coveralls.io/github/gherynos/libsaltpack?branch=main)

Dependencies
------------

* [libsodium](https://download.libsodium.org/doc/) >= 1.0.9
* [msgpack](https://github.com/msgpack/msgpack-c) >= 2.0.0

Big integer logic implemented using [Num](https://github.com/983/Num.git), included as a git submodule.

Building
--------

Here's how to build the static library on Linux or OSX:

```bash
git submodule init
git submodule update
cmake .
make
make test
make install
```

Android Native Development Kit is also supported; see [libsaltpack-jni](https://github.com/Gherynos/libsaltpack-jni).

Documentation
-------------

The classes documentation can be found here: [https://libsaltpack.gherynos.com/annotated.html](https://libsaltpack.gherynos.com/annotated.html).

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
        enc->addBlock({'T', 'h', 'e', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
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
        sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
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
        sig->addBlock({'a', ' ', 's', 'i', 'g', 'n', 'e', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
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

### Signcrypt message

#### Curve25519 key

```c++
#include <saltpack.h>
#include <sodium.h>
#include <iostream>

int main(void) {

    try {
    
        // generate signer keypair
        saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
        saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
        saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);
        
        // generate recipient keypair
        saltpack::BYTE_ARRAY receiver_publickey(crypto_box_PUBLICKEYBYTES);
        saltpack::BYTE_ARRAY receiver_secretkey(crypto_box_SECRETKEYBYTES);
        saltpack::Utils::generateKeypair(receiver_publickey, receiver_secretkey);

        // asymmetric keys
        std::list<saltpack::BYTE_ARRAY> recipients;
        recipients.push_back(receiver_publickey);

        // symmetric keys (empty)
        std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;

        // signcrypt message
        std::stringstream out;
        saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(
            aOut, signer_secretkey, recipients, symmetricKeys);
        sig->addBlock({'a', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'}, true);
        aOut.finalise();
        
        out.flush();
        delete sig;
        
        // display message
        std::cout << out.str() << std::endl;
        
        // verify message
        std::stringstream in(out.str());
        saltpack::ArmoredInputStream aIn(in);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(aIn, receiver_secretkey,
            std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>{});
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

#### Symmetric key

```c++
#include <saltpack.h>
#include <sodium.h>
#include <iostream>

int main(void) {

    try {
    
        // generate signer keypair
        saltpack::BYTE_ARRAY signer_secretkey(crypto_sign_SECRETKEYBYTES);
        saltpack::BYTE_ARRAY signer_publickey(crypto_sign_PUBLICKEYBYTES);
        saltpack::Utils::generateSignKeypair(signer_publickey, signer_secretkey);
        
        // asymmetric keys (empty)
        std::list<saltpack::BYTE_ARRAY> recipients;

        // symmetric keys
        std::list<std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY>> symmetricKeys;
        std::pair<saltpack::BYTE_ARRAY, saltpack::BYTE_ARRAY> key(
            saltpack::Utils::generateRandomBytes(32),
            saltpack::Utils::generateRandomBytes(crypto_secretbox_KEYBYTES));
        symmetricKeys.push_back(key);

        // signcrypt message
        std::stringstream out;
        saltpack::ArmoredOutputStream aOut(out, saltpack::MODE_ENCRYPTION);
        saltpack::MessageWriter *sig = new saltpack::MessageWriter(
            aOut, signer_secretkey, recipients, symmetricKeys);
        sig->addBlock({'A', ' ', 's', '3', 'c', 'r', 'e', '7'}, false);
        sig->addBlock({' ', 'm', 'e', 's', 's', '@', 'g', 'e'}, true);
        aOut.finalise();
        
        out.flush();
        delete sig;
        
        // display message
        std::cout << out.str() << std::endl;
        
        // verify message
        std::stringstream in(out.str());
        saltpack::ArmoredInputStream aIn(in);
        std::stringstream msg;
        saltpack::MessageReader *dec = new saltpack::MessageReader(aIn, saltpack::BYTE_ARRAY{}, key);
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

Author
------

> GitHub [@gherynos](https://github.com/gherynos)

License
-------

libsaltpack is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
