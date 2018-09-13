# EasyJCE

[![Build Status](https://travis-ci.org/antfarmer/easyjce.svg?branch=master)](https://travis-ci.org/antfarmer/easyjce)

**EasyJCE** provides an easy to use interface for encrypting, decrypting, and hashing data for transmission or storage using the Java Cryptographic Extension (JCE). EasyJCE supports most algorithms implemented for the JCE, including those provided by third-party encryption service providers. Integrated MAC (Message Authentication Code) support can optionally be used to ensure data integrity and indicate possible data tampering. A set of Hibernate user types is also included to transparently integrate encryption into the data layer, ensuring data is persisted in its encrypted form while obscuring encryption and decryption logic from application code. EasyJCE also provides basic encoding and decoding facilities for transmitting encrypted binary data through mediums which are limited to printable ASCII characters, such as email messages or URL's.


## Installation
### Maven
### Gradle
### Required Libraries
While the compile-time and testing dependencies are documented in the provided pom file, technically, there are no runtime dependencies for encryption. Here is a summary of the runtime requirements depending on the features needed:

- Hibernate: integration with Hibernate's UserType interface for applying encryption/hashing to POJO fields
- Bouncy Castle: password encoding and as a custom JCE provider
- Spring Security Crypto: password encoding
- Argon2Jvm: Argon2 encoding capabilities

Testing requires slf4j, logback, easymock, junit, and h2 db


## Usage
Please have a look at the [API documentation](/docs).

### TextEncoder
TextEncoder's are responsible for encoding/decoding binary data to/from ASCII-based String forms which allow you to specify keys in configuration and encrypted/hashed data in normal varchar/text database columns. 

These include Hex, Base32, and Base64 implementations, with variations for the alphabet used, depending on the application. For example, BASE64 uses `'+'` and `'/'` for encoding which are not allowed in URL parameters. The `Base64UrlEncoder` replaces these with `'-'` and `'.'` which are allowed. The default recommendation is for the `Base64Encoder`.

### Keys
In most cases, you first will need to generate some keys for encryption, unless you are using a hashing algorithm. Use methods on `CryptoUtil` to generate the keys you want.

For example, this creates a key for AES-256:
```java
	SecretKey key = CryptoUtil.generateSecretKey(AesParameters.KEY_SIZE_256, AesParameters.ALGORITHM_AES);
	String keyCfgValue = Base64Encoder.getInstance().encode(key.getEncoded());
	System.out.println(keyCfgValue);
```

This creates an asymmetric key pair for RSA-1024:
```java
	KeyPair pair = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.KEY_SIZE_1024, RsaParameters.ALGORITHM_RSA);
	String pubKeyCfgValue = Base64Encoder.getInstance().encode(pair.getPublic().getEncoded());
	String privKeyCfgValue = Base64Encoder.getInstance().encode(pair.getPrivate().getEncoded());
	System.out.println(pubKeyCfgValue);
	System.out.println(privKeyCfgValue);
```
Overloaded methods allow for use of non-default JCE Provider such as Bouncy-Castle, etc.

Keys will be used to configure your encryptors below and can be defined in a number of ways:
- passing a `Key` instance programmatically
- encoded string parameter
- passing the class name of a `KeyLoader` implementation which loads a key in any way you choose and/or from various sources

### Encryption
Encryptors allow you to encrypt and decrypt information using specified algorithms, block modes, padding, and HMAC schemes. These types of 
algorithms are reversible, so that the sensitive data can be recovered for later use. This is appropriate for storing credentials that must be
used in their original form later on, but not for storing credentials for the given application as it need not be transmitted. See the 
[Password Encoding section](#password-encoding-hashing) below for one-way hashing algorithms.

Encryptors can be created programmatically or defined via configuration (annotations or XML). System properties may also be used by specifying the system property prefix and organizing the appropriate encryption properties under that prefix. Encryptors can also be 'registered' for use JVM-wide using the `EncryptorStore` class. This can be helpful when trying to control the number of instances created through Hibernate mappings by creating them programmatically and referencing them by name in configuration.

#### Programmatic encryption
Encryption can be performed programmatically by creating an instance of `AlgorithmParameters` which can then be applied to an `Encryptor`.
Here's an example for setting up AES-256-ECB with HMAC-SHA1:
(Note: use of the `Base64Encoder` in the parameters constructor which is used to decode the key in the parameters,
	while the `Base64Encoder` in the encryptor constructor controls how encrypted values are encoded).
```java
	final AesParameters parameters = new AesParameters(Base64Encoder.getInstance())
		.setKey("GsqGjFpSQe0D+8nKLmOoFA2/mfXHzFbYXWwAyxmxhjo")
		.setBlockMode(AesParameters.BLOCK_MODE_ECB)
		.setPadding(AesParameters.PADDING_PKCS5)
		.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
		.setMacKeySize(AesParameters.MAC_KEY_SIZE_128)
	;
	final Encryptor encryptor = new Encryptor(Base64Encoder.getInstance()).setAlgorithmParameters(parameters);
	encryptor.initialize();
	final String encrypted = encryptor.encrypt("secret stuff");
	System.out.println("Encrypted: " + encrypted);
	final String decrypted = encryptor.decrypt(encrypted);
	System.out.println("Decrypted: " + decrypted);
```
The `Encryptor` can now be used to encrypt/decrypt values and objects as needed.

#### Declarative encryption via Hibernate UserType annotations
In a JPA/Hibernate environment, encryption can be declared on POJO's using annotations. This allows for encryption of the field value as it is persisted to the database, and decryption as it is read from the database back into the POJO. This allows transparent handling of sensitive data within your application.

Here is an example for AES-256-GCM: (GCM negates the need for a HMAC)
```java
	@Type(type = "org.antfarmer.ejce.hibernate.EncryptedStringType", parameters = {
		@Parameter(name = "paramClass", value = "org.antfarmer.ejce.parameter.AesParameters"),
		@Parameter(name = "paramEncoder", value = "org.antfarmer.ejce.encoder.Base64Encoder"),
		@Parameter(name = "blockMode", value = "GCM"),
		@Parameter(name = "key", value = "th8k9z2PCO9apj1GSYU86t5DP9dfmG7uRkfdGSWrnJ0"),
		@Parameter(name = "encoder", value = "org.antfarmer.ejce.encoder.Base64Encoder")
	})
	public String getSecretValue() {
		return secretValue;
	}
```

Here is an example for referencing a pre-configured encryptor in the `EncryptorStore`:
```java
	... // in some bootstrap class
	EncryptoreStore.add("com.myapp.enc.secretEncryptor", mySecretEncryptor);
	... // in POJO
	@Type(type = "org.antfarmer.ejce.hibernate.EncryptedStringType", parameters = {
		@Parameter(name = "storeKey", value = "com.myapp.enc.secretEncryptor")
	})
	public String getSecretValue() {
		return secretValue;
	}
```
It is up to you to choose the appropriate `AbstractHibernateType`, but `EncryptedStringType` is by far the most common.
More possible parameter keys and values can found in `ConfigurerUtil` and the appropriate `AlgorithmParameters` classes.

#### Encryption via Hibernate UserType using XML configuration
In a JPA/Hibernate environment, encryption can also be configured via mapping XML. This allows for encryption of the field value as it is persisted to the database, and decryption as it is read from the database back into the POJO. This allows transparent handling of sensitive data within your application.

Here is an example for AES-256-GCM: (GCM negates the need for a HMAC)
```xml
<hibernate-mapping>
	<typedef name="encryptedPassword" class="org.antfarmer.ejce.hibernate.EncryptedStringType">
		<param name="paramClass">org.antfarmer.ejce.parameter.AesParameters</param>
		<param name="paramEncoder">org.antfarmer.ejce.encoder.Base64Encoder</param>
		<param name="key">jlor+XrLXfT2ytV5lpQN0Q</param>
		<param name="macAlgorithm">HmacSHA1</param>
		<param name="macKey">fZB8/kF5BPKB/0bCiR+Rxg</param>
	</typedef>
	...
	<class name="...">
		...
		<property name="password" type="encryptedPassword"/>
		...
	</class>
</hibernate-mapping>
```
It is up to you to choose the appropriate `AbstractHibernateType`, but `EncryptedStringType` is by far the most common.
More possible parameter keys and values can found in `ConfigurerUtil` and the appropriate `AlgorithmParameters` classes.


### Password Encoding (Hashing)
Password encoders are used to encode private information that only needs to be matched later on. Because these algorithms are essentially one-way functions, the original information cannot be deciphered afterward, at least without a huge amount of computing power. This is perfect for application credentials that only need to be matched, not transmitted to any other service later on.

It is recommended to test the chosen algorithm and parameters on the applicable environments so that each hashing operation takes somewhere between 50 and 500ms, depending on the security and user experience constraints of your application. Certain algorithms also allow memory usage configuration. This can be important to adjust when weighing system performance vs. security level in preventing GPU-based brute-force attacks.

As with encryptors, password encoders can be created programmatically or defined via configuration (annotations or XML). System properties may also be used by specifying the system property prefix and organizing the appropriate password encoder properties under that prefix. Password encoders can also be 'registered' for use JVM-wide using the `PasswordEncoderStore` class. This can be helpful when trying to control the number of instances created through Hibernate mappings by creating them programmatically and referencing them by name in configuration.

As hashing algorithms age, there will eventually be a point where you will need to upgrade the chosen encoding scheme. Since these passwords cannot be deciphered, you will not be able to upgrade them altogether in a maintenance operation. You can simply change the algorithm configured for your POJO to ensure all new users and existing users' password updates are using the new scheme. In order to allow existing users you will either need to check more than one algorithm in the credential verification logic, or predetermine the password encoding scheme by looking at the encoded form. A useful feature for handling this is the "prefix" property which allows you to prefix the encoded value with the given hash scheme prefix. Most schemes already encode the parameters of the algorithm such as strength and iteration count, but it might be wise to at least indicate the scheme here, e.g. '{pbkdf2}' or '{bcrypt}', etc. The key is defined in `AbstractConfigurablePasswordEncoder.KEY_PREFIX`.

#### Programmatic password encoding
Password encoding can be performed programmatically by creating an instance of `PasswordEncoderAdapter` and setting up the specific parameters if the defaults are not sufficient.
Here's an example for setting up PBKDF2 with secret:
(Note: parameter values are optional overrides of defaults. Also note that values must be Strings).
```java
	final Properties props = new Properties();
	props.setProperty(Pbkdf2Encoder.KEY_SECRET, "secret");
	props.setProperty(Pbkdf2Encoder.KEY_HASH_LENGTH, String.valueOf(1024));
	props.setProperty(Pbkdf2Encoder.KEY_SALT_LENGTH, String.valueOf(128));
	props.setProperty(Pbkdf2Encoder.KEY_ITERATIONS, String.valueOf(200000));
	props.setProperty(Pbkdf2Encoder.KEY_ALGORITHM, Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA1);
	props.setProperty(Pbkdf2Encoder.KEY_PROVIDER_CLASS, provider.getClass().getName());
	props.setProperty(Pbkdf2Encoder.KEY_RANDOM, rc.getName());
	props.setProperty(Pbkdf2Encoder.KEY_PREFIX, "{pbkdf2}");
	// Setup encoder
	final Pbkdf2Encoder encoder = new Pbkdf2Encoder();
	encoder.configure(props, null);
	// Hash and compare
	final String encoded1 = encoder.encode("PASSWORD");
	System.out.println("Hashed1: " + encoded1);
	final String encoded2 = encoder.encode("PASSWORD");
	System.out.println("Hashed2: " + encoded2);
	System.out.println("Matches1: " + encoder.matches("PASSWORD", encoded1));
	System.out.println("Matches2: " + encoder.matches("PASSWORD", encoded2));
```
Note that each encoding will be different, but both will match the same input value.

#### Declarative password encoding via Hibernate UserType annotations
In a JPA/Hibernate environment, password encoding can be declared on POJO's using annotations. This allows for hashing of the field value as it is persisted to the database. The value retrieved from the database will remain hashed. Matching of the password will require a reference to the encoder, which can be retrieved via the `PasswordEncoderStore` after setting the name in the storeExportKey property. Except for 'encoderAdapter', the parameters are all optional overrides of default settings.

Here is an example for Argon2id:
```java
	@Type(type = "org.antfarmer.ejce.password.EncodedPasswordType", parameters = {
		@Parameter(name = "encoderAdapter", value = "org.antfarmer.ejce.password.encoder.Argon2JvmEncoder"),
		@Parameter(name = "type", value = "id"),
		@Parameter(name = "hashLen", value = "64"),	// Bytes
		@Parameter(name = "saltLen", value = "32"),	// Bytes
		@Parameter(name = "iterations", value = "100"),
		@Parameter(name = "parallelism", value = "4"),	// Threads
		@Parameter(name = "memSize", value = "65536"),	// KB
		@Parameter(name = "storeExportKey", value = "com.myapp.pswd.user")
	})
	public String getPassword() {
		return password;
	}
```

Here is an example for referencing a pre-configured password encoder in the `PasswordEncoderStore`:
```java
	... // in some bootstrap class
	PasswordEncoderStore.add("com.myapp.pswd.user", mySecretEncryptor);
	... // in POJO
	@Type(type = "org.antfarmer.ejce.password.EncodedPasswordType", parameters = {
		@Parameter(name = "storeKey", value = "com.myapp.pswd.user")
	})
	public String getPassword() {
		return password;
	}
```

In your security logic, credential verification can be checked via encoder reference:
```java
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		// rawPassword comes from user login form
		// encodedPassword comes from user.getPassword()
		return PasswordEncoderStore.get("com.myapp.pswd.user").matches(rawPassword, encodedPassword);
	}
```
More possible parameter keys and values can found in `ConfigurerUtil` and the appropriate `PasswordEncoderAdapter` classes.

#### Password encoding via Hibernate UserType using XML configuration
In a JPA/Hibernate environment, password encoding can also be configured via mapping XML. This allows for hashing of the field value as it is persisted to the database. The value retrieved from the database will remain hashed. Matching of the password will require a reference to the encoder, which can be retrieved via the `PasswordEncoderStore` after setting the name in the storeExportKey property. Except for 'encoderAdapter', the parameters are all optional overrides of default settings.

Here is an example for the BCrypt algorithm:
```xml
<hibernate-mapping>
	<typedef name="encodedPassword" class="org.antfarmer.ejce.password.EncodedPasswordType">
		<param name="encoderAdapter">org.antfarmer.ejce.password.encoder.bc.BcBcryptEncoder</param>
		<param name="version">2b</param>
		<param name="strength">7</param>
		<param name="storeExportKey">com.myapp.pswd.user</param>
	</typedef>
	...
	<class name="...">
		...
		<property name="password" type="encodedPassword"/>
		...
	</class>
</hibernate-mapping>
```
More possible parameter keys and values can found in `ConfigurerUtil` and the appropriate `PasswordEncoderAdapter` classes.


## API Documentation
Please have a look at the [API documentation](/docs).
