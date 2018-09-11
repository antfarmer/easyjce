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

import java.util.Properties;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;

/**
 * Password encoder using the Argon2 library via JNA, provided by phxql/argon2-jvm project.
 * @author Ameer Antar
 */
public class Argon2JvmEncoder extends AbstractArgon2PasswordEncoder {

	private String type;

	private int hashLengthBytes;

	private int saltLengthBytes;

	private int iterations;

	private int memorySize;

	private int parallelism;

	private Argon2 encoder;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doConfigure(final Properties parameters, final String prefix) {
		type = parseString(parameters, prefix, KEY_TYPE, DEFAULT_TYPE);
		if (!("." + TYPE_D + "." + TYPE_I + "." + TYPE_ID + ".").contains("." + type + ".")) {
        	throw new EncryptorConfigurationException("Invalid algorithm type: " + type);
		}

		hashLengthBytes = parseInt(parameters, prefix, KEY_HASH_LENGTH, DEFAULT_HASH_LENGTH);
		if (hashLengthBytes < 4) {
        	throw new EncryptorConfigurationException("Hash length must be >= 4");
		}

		saltLengthBytes = parseInt(parameters, prefix, KEY_SALT_LENGTH, DEFAULT_SALT_LENGTH);
		if (saltLengthBytes < 8) {
        	throw new EncryptorConfigurationException("Salt length must be >= 8");
		}

		iterations = parseInt(parameters, prefix, KEY_ITERATIONS, DEFAULT_ITERATIONS);
        if (iterations < 1) {
        	throw new EncryptorConfigurationException("Iterations must be >= 1");
        }

        parallelism = parseInt(parameters, prefix, KEY_PARALLELISM, DEFAULT_PARALLELISM);
        if (parallelism < 1 || parallelism > 0xffffff) {
        	throw new EncryptorConfigurationException("Parallelism must be >= 1 and <= " + 0xffffff);
        }

        final int minMemSize = 8 * parallelism;
		memorySize = parseInt(parameters, prefix, KEY_MEMORY_SIZE, DEFAULT_MEMORY_SIZE);
        if (memorySize < minMemSize) {
        	throw new EncryptorConfigurationException("Memory size must be >= " + minMemSize + " (8 * parallelism)");
        }

		encoder = Argon2Factory.create(Argon2Types.valueOf("ARGON2" + type), saltLengthBytes, hashLengthBytes);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String doEncode(final CharSequence rawPassword) {
		return encoder.hash(iterations, memorySize, parallelism, rawPassword.toString(), getCharset());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isMatch(final CharSequence rawPassword, final String encodedPassword) {
		return encoder.verify(encodedPassword, rawPassword.toString(), getCharset());
	}

}
