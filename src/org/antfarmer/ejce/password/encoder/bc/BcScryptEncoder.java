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
import java.util.Arrays;
import java.util.Properties;
import java.util.regex.Pattern;

import org.antfarmer.ejce.password.encoder.AbstractScryptPasswordEncoder;
import org.antfarmer.ejce.util.ByteUtil;
import org.antfarmer.ejce.util.TextUtil;
import org.bouncycastle.crypto.generators.SCrypt;

/**
 * Password encoder using Bouncy Castle's SCrpyt implementation.
 * @author Ameer Antar
 */
public class BcScryptEncoder extends AbstractScryptPasswordEncoder {

	private static final Pattern SPLITTER = Pattern.compile("\\$");

	private int cpuCost;

	private int memoryCost;

	private int parallelization;

	private int keyLength;

	private int saltLength;

	private SecureRandom random;

	private int minimumEncLength;

	private int maximumEncLength;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configure(final Properties parameters, final String prefix) {

		cpuCost = parseInt(parameters, prefix, KEY_CPU_COST, DEFAULT_CPU_COST);
		memoryCost = parseInt(parameters, prefix, KEY_MEM_COST, DEFAULT_MEM_COST);
		parallelization = parseInt(parameters, prefix, KEY_PARALLELIZATION, DEFAULT_PARALLELIZATION);
		keyLength = parseInt(parameters, prefix, KEY_KEY_LENGTH, DEFAULT_KEY_LENGTH);
		saltLength = parseInt(parameters, prefix, KEY_SALT_LENGTH, DEFAULT_SALT_LENGTH);
		random = getRandom(parameters, prefix);


		if (cpuCost <= 1 || cpuCost > 65536) {
			throw new IllegalArgumentException("Cpu cost parameter must be > 1 and <= 65536.");
		}
		if ((cpuCost & (cpuCost - 1)) != 0) {
			throw new IllegalArgumentException("Cpu cost must be a power of 2.");
		}
		if (memoryCost < 1 || memoryCost > 0xff) {	// header only allows up to 255
			throw new IllegalArgumentException("Memory cost must be >= 1 and < 256.");
		}
		final int maxParallel = Integer.MAX_VALUE / (128 * memoryCost * 8);
		// header only allows up to 255
		if (parallelization < 1 || parallelization > 0xff || parallelization > maxParallel) {
			throw new IllegalArgumentException("Parallelization parameter p must be >= 1 and <= "
					+ (maxParallel < 0xff ? maxParallel : 0xff)
					+ " (based on block size r of " + memoryCost + ")");
		}
		if (keyLength < 1 || keyLength > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("Key length must be >= 1 and <= " + Integer.MAX_VALUE);
		}
		if (saltLength < 1 || saltLength > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("Salt length must be >= 1 and <= " + Integer.MAX_VALUE);
		}

		minimumEncLength = 3 + 5 + (4 * (keyLength + saltLength) / 3);
		maximumEncLength = 3 + 16 + (4 * (keyLength + saltLength) / 3);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String encode(final CharSequence rawPassword) {
		final byte[] salt = new byte[saltLength];
		random.nextBytes(salt);

		final byte[] pass = toBytes(rawPassword);
		try {
			final byte[] derived = SCrypt.generate(pass, salt, cpuCost, memoryCost, parallelization, keyLength);

			final String params = Long.toString(((int) (Math.log(cpuCost) / Math.log(2)) << 16) | memoryCost << 8 | parallelization, 16);

			final StringBuilder sb = new StringBuilder(maximumEncLength);
			sb.append("$").append(params).append('$').append(encodeBytes(salt)).append('$').append(encodeBytes(derived));

			return sb.toString();
		}
		finally {
			ByteUtil.clear(pass);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
		if (!TextUtil.hasLength(encodedPassword)) {
			return false;
		}
		if (encodedPassword.length() < minimumEncLength) {
			return false;
		}
		return decodeAndCheckMatches(rawPassword, encodedPassword);
	}

	private boolean decodeAndCheckMatches(final CharSequence rawPassword, final String encodedPassword) {
		final String[] parts = SPLITTER.split(encodedPassword);

		if (parts.length != 4) {
			return false;
		}

		final long params = Long.parseLong(parts[1], 16);
		final byte[] salt = decodeBytes(parts[2]);
		final byte[] derived = decodeBytes(parts[3]);

		final int cpuExp = (int) (params >> 16 & 0xffff);
		final int cpuCost = 1 << cpuExp;
		final int memoryCost = (int) params >> 8 & 0xff;
		final int parallelization = (int) params & 0xff;

		final byte[] generated;
		final byte[] pass = toBytes(rawPassword);

		try {
			generated = SCrypt.generate(pass, salt, cpuCost, memoryCost, parallelization, keyLength);
		}
		finally {
			ByteUtil.clear(pass);
		}

		return Arrays.equals(derived, generated);
	}

}
