# easyjce

[![Build Status](https://travis-ci.org/antfarmer/easyjce.svg?branch=master)](https://travis-ci.org/antfarmer/easyjce)

**EasyJCE** provides an easy to use interface for encrypting and decrypting data for transmission or storage using the Java Cryptographic Extension (JCE). EasyJCE supports most algorithms implemented for the JCE, including those provided by third-party encryption service providers. Integrated MAC (Message Authentication Code) support can optionally be used to ensure data integrity and indicate possible data tampering. A set of Hibernate user types is also included to transparently integrate encryption into the data layer, ensuring data is persisted in its encrypted form while obscuring encryption and decryption logic from application code. EasyJCE also provides basic encoding and decoding facilities for transmitting encrypted binary data through mediums which are limited to printable ASCII characters, such as email messages or URL's.
