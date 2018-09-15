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
package org.antfarmer.ejce.test.parameter;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.parameter.BlowfishParameters;
import org.antfarmer.ejce.parameter.key_loader.KeyLoader;
import org.antfarmer.ejce.util.CryptoUtil;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class BasicParametersTest {

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
	private static final Random random = new Random();

	@Test
	public void testSetEncKey() throws GeneralSecurityException {
		final byte[] keyBytes = new byte[8];
		random.nextBytes(keyBytes);
		final byte[] copy = Arrays.clone(keyBytes);

		final BlowfishParameters params = new BlowfishParameters();
		params.setKey(keyBytes);
		assertArrayEquals(copy, params.getKey().getEncoded());
		assertArrayEquals(new byte[keyBytes.length], keyBytes);
	}

	@Test
	public void testSetMacKey() throws GeneralSecurityException {
		final byte[] keyBytes = new byte[8];
		random.nextBytes(keyBytes);

		final BlowfishParameters params = new BlowfishParameters();
		assertNull(params.getMacKey());
		final Key key = CryptoUtil.getSecretKeyFromRawKey(keyBytes, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		params.setMacKey(key);
		params.setMacAlgorithm(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		assertArrayEquals(keyBytes, params.getMacKey().getEncoded());
	}

	@Test
	public void testSetMacKeyBytes() throws GeneralSecurityException {
		final byte[] keyBytes = new byte[8];
		random.nextBytes(keyBytes);
		final byte[] copy = Arrays.clone(keyBytes);

		final BlowfishParameters params = new BlowfishParameters();
		assertNull(params.getMacKey());
		params.setMacKey(keyBytes);
		params.setMacAlgorithm(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		assertArrayEquals(copy, params.getMacKey().getEncoded());
		assertArrayEquals(new byte[keyBytes.length], keyBytes);
	}

	@Test
	public void testSetMacKeyString() throws GeneralSecurityException {
		final String key = "01234567";

		final BlowfishParameters params = new BlowfishParameters();
		assertNull(params.getMacKey());
		params.setMacKey(key);
		params.setMacAlgorithm(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		assertArrayEquals(key.getBytes(DEFAULT_CHARSET), params.getMacKey().getEncoded());
	}

	@Test
	public void testSetMacKeyLoader() throws GeneralSecurityException {
		final BlowfishParameters params = new BlowfishParameters();
		assertNull(params.getMacKey());
		params.setMacKeyLoader(new MacKeyLoader());
		params.setMacAlgorithm(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		params.getMacKey();
		assertArrayEquals(MacKeyLoader.key.getEncoded(), params.getMacKey().getEncoded());
	}

	private static class MacKeyLoader implements KeyLoader {
		private static Key key;
		@Override
		public Key loadKey(final String algorithm) {
			try {
				return key = CryptoUtil.generateSecretKey(BlowfishParameters.MAC_KEY_SIZE_128, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
			}
			catch (final NoSuchAlgorithmException e) {
				throw new EncryptorConfigurationException(e);
			}
		}

	}
}
