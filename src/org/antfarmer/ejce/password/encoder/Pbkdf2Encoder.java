/*
 * Copyright 2018 Ameer Antar.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.antfarmer.ejce.password.encoder;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.util.EnvironmentUtil;
import org.antfarmer.ejce.util.TextUtil;

/**
 * A highly configurable password encoder using PBKDF2 algorithms.
 * @author Ameer Antar
 */
public class Pbkdf2Encoder extends AbstractPbkdf2PasswordEncoder {

	/**
	 * Property key for the salt length in bits. The default is currently 64.
	 */
	public static final String KEY_SALT_LENGTH = "saltLen";

	/**
	 * Property key for the JCE provider name to be used to load the algorithm.
	 */
	public static final String KEY_PROVIDER_NAME = "providerName";

	/**
	 * Property key for the JCE provider class to be used to load the algorithm.
	 */
	public static final String KEY_PROVIDER_CLASS = "providerClass";

	/**
	 * The PBKDF2withHmacSHA1 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA1 = "PBKDF2withHmacSHA1";

	/**
	 * The PBKDF2withHmacSHA224 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA224 = "PBKDF2withHmacSHA224";

	/**
	 * The PBKDF2withHmacSHA256 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA256 = "PBKDF2withHmacSHA256";

	/**
	 * The PBKDF2withHmacSHA384 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA384 = "PBKDF2withHmacSHA384";

	/**
	 * The PBKDF2withHmacSHA512 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA512 = "PBKDF2withHmacSHA512";

	/**
	 * The PBKDF2withHmacSHA3-224 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA3_224 = "PBKDF2withHmacSHA3-224";

	/**
	 * The PBKDF2withHmacSHA3-256 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA3_256 = "PBKDF2withHmacSHA3-256";

	/**
	 * The PBKDF2withHmacSHA3-384 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA3_384 = "PBKDF2withHmacSHA3-384";

	/**
	 * The PBKDF2withHmacSHA3-512 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_SHA3_512 = "PBKDF2withHmacSHA3-512";

	/**
	 * The PBKDF2withHmacGOST3411 algorithm.
	 */
	public static final String ALGORITHM_PBKDF2_HMAC_GOST = "PBKDF2withHmacGOST3411";

	/**
	 * The default algorithm value (PBKDF2withHmacSHA1 or PBKDF2withHmacSHA512 [JRE >= 1.8]), if no value is specified.
	 */
	public static final String DEFAULT_ALGORITHM = EnvironmentUtil.JAVA_VERSION >= 1.8 ? ALGORITHM_PBKDF2_HMAC_SHA512 : ALGORITHM_PBKDF2_HMAC_SHA1;

	/**
	 * The default salt length in bits if no value is specified.
	 */
	public static final int DEFAULT_SALT_LENGTH = 64;

	private byte[] secret;

	private int hashLengthBits;

	private int saltLengthBytes;

	private int iterations;

	private String algorithm;

	private SecureRandom random;

	private SecretKeyFactory skf;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configure(final Properties parameters, final String prefix) {
		secret = toBytes(parseString(parameters, prefix, KEY_SECRET, ""));

		hashLengthBits = parseInt(parameters, prefix, KEY_HASH_LENGTH, DEFAULT_HASH_LENGTH);
		if (hashLengthBits < 1) {
			throw new EncryptorConfigurationException("Hash length must be > 0");
		}

		final int saltLengthBits = parseInt(parameters, prefix, KEY_SALT_LENGTH, DEFAULT_SALT_LENGTH);
		if (saltLengthBits % 8 != 0) {
			throw new EncryptorConfigurationException("Salt length must be specified in bits and must be a multiple of 8");
		}
		saltLengthBytes = saltLengthBits / 8;

		iterations = parseInt(parameters, prefix, KEY_ITERATIONS, DEFAULT_ITERATIONS);
		if (iterations < 1) {
			throw new EncryptorConfigurationException("Iterations must be > 0");
		}

		algorithm = parseString(parameters, prefix, KEY_ALGORITHM, DEFAULT_ALGORITHM);

		final String providerName = parseString(parameters, prefix, KEY_PROVIDER_NAME, null);

		// load provider instance if needed
		Provider provider = null;
		final String providerClass = parseString(parameters, prefix, KEY_PROVIDER_CLASS, null);
		if (TextUtil.hasLength(providerClass)) {
			try {
				provider = (Provider) Class.forName(providerClass).newInstance();
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error instantiating: " + providerClass, e);
			}
		}

		// load SecretKeyFactory using algorithm and provider, if any
		try {
			if (provider != null) {
				skf = SecretKeyFactory.getInstance(algorithm, provider);
			}
			else if (TextUtil.hasLength(providerName)) {
				skf = SecretKeyFactory.getInstance(algorithm, providerName);
			}
			else {
				skf = SecretKeyFactory.getInstance(algorithm);
			}
		}
		catch (final GeneralSecurityException e) {
			throw new EncryptorConfigurationException("Error initializing algorithm: " + algorithm, e);
		}

		random = getRandom(parameters, prefix);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String encode(final CharSequence rawPassword) {
		final byte[] salt = new byte[saltLengthBytes];
		random.nextBytes(salt);
		return encodeBytes(encode(rawPassword, salt));
	}

	private byte[] encode(final CharSequence rawPassword, final byte[] salt) {
		final char[] rawPsd = rawPassword.toString().toCharArray();
		final byte[] saltySecret = concatenate(salt, secret);
		final PBEKeySpec spec = new PBEKeySpec(rawPsd, saltySecret, iterations, hashLengthBits);
		try {
			return concatenate(salt, skf.generateSecret(spec).getEncoded());
		}
		catch (final GeneralSecurityException e) {
			throw new IllegalStateException("Could not create hash", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
		final byte[] decoded = decodeBytes(encodedPassword);
		final byte[] salt = Arrays.copyOfRange(decoded, 0, saltLengthBytes);
		return Arrays.equals(decoded, encode(rawPassword, salt));
	}

	private byte[] concatenate(final byte[]... arrays) {
		int length = 0;
		for (final byte[] array : arrays) {
			length += array.length;
		}
		final byte[] newArray = new byte[length];
		int destPos = 0;
		for (final byte[] array : arrays) {
			System.arraycopy(array, 0, newArray, destPos, array.length);
			destPos += array.length;
		}
		return newArray;
	}
}
