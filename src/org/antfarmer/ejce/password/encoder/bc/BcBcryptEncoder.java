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
package org.antfarmer.ejce.password.encoder.bc;

import java.security.SecureRandom;
import java.util.Properties;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.password.encoder.AbstractBcryptPasswordEncoder;
import org.antfarmer.ejce.util.ByteUtil;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/**
 * Password encoder using Bouncy Castle's OpenBSD BCrpyt implementation.
 * @author Ameer Antar
 */
public class BcBcryptEncoder extends AbstractBcryptPasswordEncoder {

	/**
	 * Property key for the version to use, 2a, 2y, or 2b. Default is 2b.
	 */
	public static final String KEY_VERSION = "version";

	/**
	 * The '2a' version.
	 */
	public static final String VERSION_2A = "2a";

	/**
	 * The '2y' version.
	 */
	public static final String VERSION_2Y = "2y";

	/**
	 * The '2b' version.
	 */
	public static final String VERSION_2B = "2b";

	/**
	 * The default version '2b', if no value is specified.
	 */
	public static final String DEFAULT_VERSION = VERSION_2B;

	private static final int SALT_LENGTH = 16;	// (128 bits / 8)

	private String version;

	private int strength;

	private SecureRandom random;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doConfigure(final Properties parameters, final String prefix) {
		version = parseString(parameters, prefix, KEY_VERSION, DEFAULT_VERSION);
		if (!("." + VERSION_2A + "." + VERSION_2Y + "." + VERSION_2B + ".").contains("." + version + ".")) {
        	throw new EncryptorConfigurationException("Invalid version: " + version);
		}

		strength = parseInt(parameters, prefix, KEY_STRENGTH, DEFAULT_STRENGTH);
        if (strength < 4 || strength > 31) {
        	throw new EncryptorConfigurationException("Strength must be between 4 and 31");
        }

		random = getRandom(parameters, prefix);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String doEncode(final CharSequence rawPassword) {
		final byte[] salt = new byte[SALT_LENGTH];
		random.nextBytes(salt);
		final char[] pass = rawPassword.toString().toCharArray();
		try {
			return OpenBSDBCrypt.generate(version, pass, salt, strength);
		}
		finally {
			ByteUtil.clear(pass);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isMatch(final CharSequence rawPassword, final String encodedPassword) {
		final char[] pass = rawPassword.toString().toCharArray();
		try {
			return OpenBSDBCrypt.checkPassword(encodedPassword, pass);
		}
		finally {
			ByteUtil.clear(pass);
		}
	}

}
