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
package org.antfarmer.ejce.test.password.encoder.spring;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.antfarmer.ejce.password.encoder.spring.SpringPbkdf2Encoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

/**
 * @author Ameer Antar
 */
public class SpringPbkdf2Test extends AbstractPasswordTest<SpringPbkdf2Encoder> {

	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final String secret = "SeCr3t";
		final int hashLen = 256;
		final int iterations = 20000;
		final String algo = SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256.name();

		final Properties props = new Properties();
		props.setProperty(SpringPbkdf2Encoder.KEY_SECRET, secret);
		props.setProperty(SpringPbkdf2Encoder.KEY_HASH_LENGTH, String.valueOf(hashLen));
		props.setProperty(SpringPbkdf2Encoder.KEY_ITERATIONS, String.valueOf(iterations));
		props.setProperty(SpringPbkdf2Encoder.KEY_ALGORITHM, algo);
		props.setProperty(SpringPbkdf2Encoder.KEY_ENCODE_HEX, String.valueOf(true));
		final SpringPbkdf2Encoder encoder = createEncoder(props);

		final Pbkdf2PasswordEncoder pswdEnc = ReflectionUtil.getFieldValue(encoder, "pswdEnc");
		assertArrayEquals(toBytes(secret), (byte[]) ReflectionUtil.getFieldValue(pswdEnc, "secret"));
		assertEquals(Integer.valueOf(hashLen), ReflectionUtil.getFieldValue(pswdEnc, "hashWidth"));
		assertEquals(Integer.valueOf(iterations), ReflectionUtil.getFieldValue(pswdEnc, "iterations"));
		assertEquals(algo, ReflectionUtil.getFieldValue(pswdEnc, "algorithm"));
		assertFalse((Boolean) ReflectionUtil.getFieldValue(pswdEnc, "encodeHashAsBase64"));

		final String encoded = encoder.encode(PASSWORD);
		assertFalse(PASSWORD.equals(encoded));
		assertTrue(encoder.matches(PASSWORD, encoded));
	}

	@Test
	public void testConfigureBad() {
		final Properties props = new Properties();
		props.setProperty(SpringPbkdf2Encoder.KEY_HASH_LENGTH, "0");
		assertException(props, "Hash");

		props.setProperty(SpringPbkdf2Encoder.KEY_HASH_LENGTH, "10");
		props.setProperty(SpringPbkdf2Encoder.KEY_ITERATIONS, "0");
		assertException(props, "Iterations");
	}

	@Override
	protected SpringPbkdf2Encoder createEncoder() {
		final Properties props = new Properties();
		props.setProperty(SpringPbkdf2Encoder.KEY_ITERATIONS, String.valueOf(50000));
		return createEncoder(props);
	}

	@Override
	protected SpringPbkdf2Encoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(SpringPbkdf2Encoder.KEY_ITERATIONS, String.valueOf(3000));
		return createEncoder(props);
	}

	@Override
	protected SpringPbkdf2Encoder createEncoder(final Properties defaults) {
		final SpringPbkdf2Encoder encoder = new SpringPbkdf2Encoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
