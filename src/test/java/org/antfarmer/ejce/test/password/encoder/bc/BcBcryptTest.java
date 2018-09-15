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
package org.antfarmer.ejce.test.password.encoder.bc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.Properties;

import org.antfarmer.ejce.password.encoder.bc.BcBcryptEncoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class BcBcryptTest extends AbstractPasswordTest<BcBcryptEncoder> {

	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final String version = "2y";
		final int strength = 9;
		final Class<? extends SecureRandom> rc = MyRandom.class;
		final Properties props = new Properties();
		props.setProperty(BcBcryptEncoder.KEY_VERSION, String.valueOf(version));
		props.setProperty(BcBcryptEncoder.KEY_STRENGTH, String.valueOf(strength));
		props.setProperty(BcBcryptEncoder.KEY_RANDOM, rc.getName());
		props.setProperty(BcBcryptEncoder.KEY_PREFIX, "{bcrypt}");
		final BcBcryptEncoder encoder = createEncoder(props);

		assertEquals(version, ReflectionUtil.getFieldValue(encoder, "version"));
		assertEquals(Integer.valueOf(strength), ReflectionUtil.getFieldValue(encoder, "strength"));
		assertSame(rc, ReflectionUtil.getFieldValue(encoder, "random").getClass());

		final String encoded = encoder.encode(PASSWORD);
		assertFalse(PASSWORD.equals(encoded));
		assertTrue(encoded.startsWith("{bcrypt}"));
		assertTrue(encoder.matches(PASSWORD, encoded));
	}

	@Test
	public void testConfigureBad() {
		final Properties props = new Properties();
		props.setProperty(BcBcryptEncoder.KEY_VERSION, "2v");

		assertException(props, "version");

		props.setProperty(BcBcryptEncoder.KEY_VERSION, String.valueOf(BcBcryptEncoder.VERSION_2Y));
		props.setProperty(BcBcryptEncoder.KEY_STRENGTH, String.valueOf(1));
		assertException(props, "Strength");
	}

	@Override
	protected BcBcryptEncoder createEncoder() {
		return createEncoder(null);
	}

	@Override
	protected BcBcryptEncoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(BcBcryptEncoder.KEY_STRENGTH, String.valueOf(7));
		return createEncoder(props);
	}

	@Override
	protected BcBcryptEncoder createEncoder(final Properties defaults) {
		final BcBcryptEncoder encoder = new BcBcryptEncoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
