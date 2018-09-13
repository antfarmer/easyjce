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
package org.antfarmer.ejce.password.encoder.spring;

import java.util.Properties;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.password.encoder.AbstractPbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

/**
 * Password encoder using Spring's PBKDF2 implementation.
 * @author Ameer Antar
 */
public class SpringPbkdf2Encoder extends AbstractPbkdf2PasswordEncoder {

	/**
	 * The default algorithm value (PBKDF2WithHmacSHA512), if no value is specified.
	 */
	public static final String DEFAULT_ALGORITHM = SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512.name();

	/**
	 * Property key for the flag indicating whether to encode values using a hex encoder. The default is
	 * false.
	 */
	public static final String KEY_ENCODE_HEX = "encodeHex";


	private Pbkdf2PasswordEncoder pswdEnc;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doConfigure(final Properties parameters, final String prefix) {

		final int hashLengthBits = parseInt(parameters, prefix, KEY_HASH_LENGTH, DEFAULT_HASH_LENGTH);
		if (hashLengthBits < 1) {
			throw new EncryptorConfigurationException("Hash length must be > 0");
		}

		final int iterations = parseInt(parameters, prefix, KEY_ITERATIONS, DEFAULT_ITERATIONS);
		if (iterations < 1) {
			throw new EncryptorConfigurationException("Iterations must be > 0");
		}

		pswdEnc = new Pbkdf2PasswordEncoder(
				parseString(parameters, prefix, KEY_SECRET, ""),
				iterations,
				hashLengthBits
		);

		final String algo = parseString(parameters, prefix, KEY_ALGORITHM, DEFAULT_ALGORITHM);
		pswdEnc.setAlgorithm(SecretKeyFactoryAlgorithm.valueOf(algo));

		pswdEnc.setEncodeHashAsBase64(! parseBoolean(parameters, prefix, KEY_ENCODE_HEX, false));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String doEncode(final CharSequence rawPassword) {
		return pswdEnc.encode(rawPassword);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isMatch(final CharSequence rawPassword, final String encodedPassword) {
		return pswdEnc.matches(rawPassword, encodedPassword);
	}

}
