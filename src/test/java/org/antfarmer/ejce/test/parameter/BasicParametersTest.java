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

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.parameter.BlowfishParameters;
import org.antfarmer.ejce.parameter.key_loader.AbstractSymmetricKeyLoader;
import org.antfarmer.ejce.test.AbstractTest;
import org.antfarmer.ejce.util.CryptoUtil;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class BasicParametersTest extends AbstractTest {

	@Test
	public void testSetEncKey() throws GeneralSecurityException {
		final byte[] keyBytes = new byte[8];
		RANDOM.nextBytes(keyBytes);
		final byte[] copy = Arrays.clone(keyBytes);

		final BlowfishParameters params = new BlowfishParameters();
		params.setKey(keyBytes);
		assertArrayEquals(copy, params.getKey().getEncoded());
		assertArrayEquals(new byte[keyBytes.length], keyBytes);
	}

	@Test
	public void testSetKeyLoader() throws GeneralSecurityException {
		final BlowfishParameters params = new BlowfishParameters();
		params.setKeyLoader(new MyKeyLoader());
		params.getKey();
		assertArrayEquals(MyKeyLoader.key.getEncoded(), params.getKey().getEncoded());
	}

	@Test
	public void testSetBadKeyLoader() throws GeneralSecurityException {
		final Class<? extends Throwable> exc = EncryptorConfigurationException.class;

		assertException(exc, "instantiating", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setKeyLoader("o");
			}
		});

		assertException(exc, "instantiating", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setKeyLoader(String.class.getName());
			}
		});

		assertException(exc, "instantiating", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setKeyLoader(Integer.class.getName());
			}
		});

		assertException(exc, "must either be a KeyLoader", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setKeyLoader(new Integer(4));
			}
		});

	}

	@Test
	public void testSetMacKey() throws GeneralSecurityException {
		final byte[] keyBytes = new byte[8];
		RANDOM.nextBytes(keyBytes);

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
		RANDOM.nextBytes(keyBytes);
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
		assertArrayEquals(key.getBytes(UTF8), params.getMacKey().getEncoded());
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

	@Test
	public void testSetBadMacKeyLoader() throws GeneralSecurityException {
		final Class<? extends Throwable> exc = EncryptorConfigurationException.class;

		assertException(exc, "instantiating", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setMacKeyLoader("o").getMacKey();
			}
		});

		assertException(exc, "instantiating", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setMacKeyLoader(String.class.getName()).getMacKey();
			}
		});

		assertException(exc, "instantiating", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setMacKeyLoader(Integer.class.getName()).getMacKey();
			}
		});

		assertException(exc, "must either be a KeyLoader", new Operation() {
			@Override
			public void run() throws Throwable {
				new BlowfishParameters().setMacKeyLoader(new Integer(5)).getMacKey();
			}
		});

	}

	private static class MyKeyLoader extends AbstractSymmetricKeyLoader {
		private static Key key;
		@Override
		protected byte[] loadRawKey() {
			try {
				key = CryptoUtil.generateSecretKey(BlowfishParameters.KEY_SIZE_128, BlowfishParameters.ALGORITHM_BLOWFISH);
			}
			catch (final NoSuchAlgorithmException e) {
				throw new EncryptorConfigurationException(e);
			}
			return key.getEncoded();
		}

	}
	private static class MacKeyLoader extends AbstractSymmetricKeyLoader {
		private static Key key;
		@Override
		protected byte[] loadRawKey() {
			try {
				key = CryptoUtil.generateSecretKey(BlowfishParameters.MAC_KEY_SIZE_128, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
			}
			catch (final NoSuchAlgorithmException e) {
				throw new EncryptorConfigurationException(e);
			}
			return key.getEncoded();
		}

	}
}
