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
package org.antfarmer.ejce.test.password.encoder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Properties;

import javax.crypto.SecretKeyFactory;

import org.antfarmer.ejce.password.encoder.Pbkdf2Encoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class Pbkdf2Test extends AbstractPasswordTest<Pbkdf2Encoder> {

	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final String secret = "SeCr3t";
		final int hashLen = 128;
		final int saltLen = 32;
		final int iterations = 100;
		final Class<? extends SecureRandom> rc = MyRandom.class;
		final Provider provider = new BouncyCastleProvider();

		final String[] algos = {
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA1,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA224,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA256,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA384,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA512,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA3_224,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA3_256,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA3_384,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_SHA3_512,
				Pbkdf2Encoder.ALGORITHM_PBKDF2_HMAC_GOST
		};

		for (final String algo : algos) {
			final Properties props = new Properties();
			props.setProperty(Pbkdf2Encoder.KEY_SECRET, secret);
			props.setProperty(Pbkdf2Encoder.KEY_HASH_LENGTH, String.valueOf(hashLen));
			props.setProperty(Pbkdf2Encoder.KEY_SALT_LENGTH, String.valueOf(saltLen));
			props.setProperty(Pbkdf2Encoder.KEY_ITERATIONS, String.valueOf(iterations));
			props.setProperty(Pbkdf2Encoder.KEY_ALGORITHM, algo);
			props.setProperty(Pbkdf2Encoder.KEY_PROVIDER_CLASS, provider.getClass().getName());
			props.setProperty(Pbkdf2Encoder.KEY_RANDOM, rc.getName());
			props.setProperty(Pbkdf2Encoder.KEY_PREFIX, "{pbkdf2}");
			final Pbkdf2Encoder encoder = createEncoder(props);

			assertArrayEquals(toBytes(secret), (byte[]) ReflectionUtil.getFieldValue(encoder, "secret"));
			assertEquals(Integer.valueOf(hashLen), ReflectionUtil.getFieldValue(encoder, "hashLengthBits"));
			assertEquals(Integer.valueOf(saltLen / 8), ReflectionUtil.getFieldValue(encoder, "saltLengthBytes"));
			assertEquals(Integer.valueOf(iterations), ReflectionUtil.getFieldValue(encoder, "iterations"));
			assertEquals(algo, ReflectionUtil.getFieldValue(encoder, "algorithm"));
			assertSame(provider.getClass(), ((SecretKeyFactory) ReflectionUtil.getFieldValue(encoder, "skf")).getProvider().getClass());
			assertSame(rc, ReflectionUtil.getFieldValue(encoder, "random").getClass());

			final String encoded = encoder.encode(PASSWORD);
			assertFalse(PASSWORD.equals(encoded));
			assertTrue(encoded.startsWith("{pbkdf2}"));
			assertTrue(encoder.matches(PASSWORD, encoded));
		}
	}

	@Test
	public void testConfigureBad() {
		final Properties props = new Properties();
		props.setProperty(Pbkdf2Encoder.KEY_HASH_LENGTH, "0");
		assertException(props, "Hash");

		props.setProperty(Pbkdf2Encoder.KEY_HASH_LENGTH, "10");
		props.setProperty(Pbkdf2Encoder.KEY_SALT_LENGTH, "5");
		assertException(props, "Salt");

		props.setProperty(Pbkdf2Encoder.KEY_SALT_LENGTH, "8");
		props.setProperty(Pbkdf2Encoder.KEY_ITERATIONS, "0");
		assertException(props, "Iterations");

		props.setProperty(Pbkdf2Encoder.KEY_ITERATIONS, "100");
		props.setProperty(Pbkdf2Encoder.KEY_PROVIDER_CLASS, "o");
		assertException(props, "instantiating");
		props.setProperty(Pbkdf2Encoder.KEY_PROVIDER_CLASS, Integer.class.getName());
		assertException(props, "instantiating");
		props.setProperty(Pbkdf2Encoder.KEY_PROVIDER_CLASS, String.class.getName());
		assertException(props, "instantiating");

		props.remove(Pbkdf2Encoder.KEY_PROVIDER_CLASS);
		props.setProperty(Pbkdf2Encoder.KEY_ALGORITHM, "o");
		assertException(props, "initializing algorithm");
	}

	@Test
	public void testConfigureRandom() throws NoSuchFieldException, IllegalAccessException {
		final Properties props = new Properties();
		props.setProperty(Pbkdf2Encoder.KEY_RANDOM, "");

		final Pbkdf2Encoder enc = createEncoder(props);
		assertSame(SecureRandom.class, ReflectionUtil.getFieldValue(enc, "random").getClass());

		props.setProperty(Pbkdf2Encoder.KEY_RANDOM, "c");
		assertException(props, "Error creating instance");
	}

	@Override
	protected Pbkdf2Encoder createEncoder() {
		final Properties props = new Properties();
		props.setProperty(Pbkdf2Encoder.KEY_ITERATIONS, String.valueOf(50000));
		return createEncoder(props);
	}

	@Override
	protected Pbkdf2Encoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(Pbkdf2Encoder.KEY_ITERATIONS, String.valueOf(2000));
		return createEncoder(props);
	}

	@Override
	protected Pbkdf2Encoder createEncoder(final Properties defaults) {
		final Pbkdf2Encoder encoder = new Pbkdf2Encoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
