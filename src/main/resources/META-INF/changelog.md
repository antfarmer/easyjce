# EasyJCE Changelog

# [1.0.0] - 2018-09-12
- add password encoding functionality including a Hibernate UserType for the following algorithms: Argon2, BCrypt, PBKDF2, and SCrypt
- add support for GCM block mode as well as newer HMAC schemes beyond SHA1
- add MessageDigestUtil for simple hashing operations
- allow use of streams to be configurable in hibernate lob types
- drop support of java 5 and use jdbc4 which can set binary streams without length
- use static SecureRandom references as these are thread-safe and can be slow to instantiate
- add support for configuring the charset used for encoding/decoding strings, and set default to UTF-8
# [0.9.9] - 2018-08-27
- support hibernate 4
- increase default maximum stream in-memory buffer size to 512k for LOB types
- allow default buffer size and max stream in-memory buffer size to be configurable for LOB types
# [0.982] - 2011-11-22
- removed commons-logging dependency
# [0.981] - 2011-02-21
- modify return type of ReflectionUtil#getFieldValue to use generic type
# [0.98]
- added support for pure streaming in blob/clob/text Hibernate types for JDBC4
	environments
# [0.97]
- added blob/clob Hibernate types with compression support
# [0.962]
- fixed bug in ConfigurerUtil
# [0.961]
- cleaned up Base 32/64 encoders
# [0.96]
- added asymmetric key support, including RSA and ElGamal algorithms
- added SaltGenerator and SaltMatcher interfaces to allow custom salt 
	generation and matching
- added overrides for encryption/decryption methods to allow for 
	different keys for each call
- fixed key generation for PBEParameters
- converted RuntimeException's to GeneralSecurityException's

# [0.95]
- reduced memory usage for Base 32/64 encoders
- improved performance of text encoders
- added ByteUtil for converting numbers to and from byte arrays
- converted synchronized blocks to use ReentrantLock's
- removed calls to initialize() in encrypt and decrypt methods; now 
	Encryptor must be fully initialized before use

# [0.941]
- added capability to allow unsalted PBE encryption

# [0.94]
- added capability to configure Encryptor from System properties or 
	properties file
- fixed InvalidAlgorithmParameterException when using ECB block mode

# [0.93]
- made padding optional for text encoders
