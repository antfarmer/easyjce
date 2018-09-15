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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.antfarmer.ejce.password.encoder.Argon2JvmEncoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class Argon2JvmTest extends AbstractPasswordTest<Argon2JvmEncoder> {

	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final int hashLen = 64;
		final int saltLen = 32;
		final int iterations = 5;
		final int memSize = 512;
		final int parallelism = 4;

		final String[] types = {
				Argon2JvmEncoder.TYPE_D,
				Argon2JvmEncoder.TYPE_I,
				Argon2JvmEncoder.TYPE_ID
		};

		for (final String type : types) {
			final Properties props = new Properties();
			props.setProperty(Argon2JvmEncoder.KEY_TYPE, type);
			props.setProperty(Argon2JvmEncoder.KEY_HASH_LENGTH, String.valueOf(hashLen));
			props.setProperty(Argon2JvmEncoder.KEY_SALT_LENGTH, String.valueOf(saltLen));
			props.setProperty(Argon2JvmEncoder.KEY_ITERATIONS, String.valueOf(iterations));
			props.setProperty(Argon2JvmEncoder.KEY_MEMORY_SIZE, String.valueOf(memSize));
			props.setProperty(Argon2JvmEncoder.KEY_PARALLELISM, String.valueOf(parallelism));
			final Argon2JvmEncoder encoder = createEncoder(props);

			assertEquals(type, ReflectionUtil.getFieldValue(encoder, "type"));
			assertEquals(Integer.valueOf(hashLen), ReflectionUtil.getFieldValue(encoder, "hashLengthBytes"));
			assertEquals(Integer.valueOf(saltLen), ReflectionUtil.getFieldValue(encoder, "saltLengthBytes"));
			assertEquals(Integer.valueOf(iterations), ReflectionUtil.getFieldValue(encoder, "iterations"));
			assertEquals(Integer.valueOf(memSize), ReflectionUtil.getFieldValue(encoder, "memorySize"));
			assertEquals(Integer.valueOf(parallelism), ReflectionUtil.getFieldValue(encoder, "parallelism"));

			final String encoded = encoder.encode(PASSWORD);
			assertFalse(PASSWORD.equals(encoded));
			assertTrue(encoder.matches(PASSWORD, encoded));
		}
	}

	@Test
	public void testConfigureBad() {
		final Properties props = new Properties();
		props.setProperty(Argon2JvmEncoder.KEY_TYPE, "0");
		assertException(props, "algorithm type");

		props.setProperty(Argon2JvmEncoder.KEY_TYPE, Argon2JvmEncoder.TYPE_D);
		props.setProperty(Argon2JvmEncoder.KEY_HASH_LENGTH, "2");
		assertException(props, "Hash");

		props.setProperty(Argon2JvmEncoder.KEY_HASH_LENGTH, "10");
		props.setProperty(Argon2JvmEncoder.KEY_SALT_LENGTH, "5");
		assertException(props, "Salt");

		props.setProperty(Argon2JvmEncoder.KEY_SALT_LENGTH, "8");
		props.setProperty(Argon2JvmEncoder.KEY_ITERATIONS, "0");
		assertException(props, "Iterations");

		props.setProperty(Argon2JvmEncoder.KEY_ITERATIONS, "20");
		props.setProperty(Argon2JvmEncoder.KEY_PARALLELISM, "0");
		assertException(props, "Parallelism");
		props.setProperty(Argon2JvmEncoder.KEY_PARALLELISM, String.valueOf(Integer.MAX_VALUE));
		assertException(props, "Parallelism");

		props.setProperty(Argon2JvmEncoder.KEY_PARALLELISM, "1");
		props.setProperty(Argon2JvmEncoder.KEY_MEMORY_SIZE, "0");
		assertException(props, "Memory");
		props.setProperty(Argon2JvmEncoder.KEY_MEMORY_SIZE, "5");
		assertException(props, "Memory");
	}

	@Override
	protected Argon2JvmEncoder createEncoder() {
		final Properties props = new Properties();
		return createEncoder(props);
	}

	@Override
	protected Argon2JvmEncoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(Argon2JvmEncoder.KEY_ITERATIONS, String.valueOf(5));
		props.setProperty(Argon2JvmEncoder.KEY_MEMORY_SIZE, String.valueOf(512));
		props.setProperty(Argon2JvmEncoder.KEY_PARALLELISM, String.valueOf(4));
		return createEncoder(props);
	}

	@Override
	protected Argon2JvmEncoder createEncoder(final Properties defaults) {
		final Argon2JvmEncoder encoder = new Argon2JvmEncoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
