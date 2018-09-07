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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.Properties;

import org.antfarmer.ejce.password.encoder.spring.SpringBcryptEncoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Ameer Antar
 */
public class SpringBcryptTest extends AbstractPasswordTest<SpringBcryptEncoder> {

	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final int strength = 8;
		final Class<? extends SecureRandom> rc = MyRandom.class;
		final Properties props = new Properties();
		props.setProperty(SpringBcryptEncoder.KEY_STRENGTH, String.valueOf(strength));
		props.setProperty(SpringBcryptEncoder.KEY_RANDOM, rc.getName());
		final SpringBcryptEncoder encoder = createEncoder(props);

		final BCryptPasswordEncoder pswdEncoder = ReflectionUtil.getFieldValue(encoder, "pswdEncoder");
		assertEquals(Integer.valueOf(strength), ReflectionUtil.getFieldValue(pswdEncoder, "strength"));
		assertSame(rc, ReflectionUtil.getFieldValue(pswdEncoder, "random").getClass());

		final String encoded = encoder.encode(PASSWORD);
		assertFalse(PASSWORD.equals(encoded));
		assertTrue(encoder.matches(PASSWORD, encoded));
	}

	@Override
	protected SpringBcryptEncoder createEncoder() {
		return createEncoder(null);
	}

	@Override
	protected SpringBcryptEncoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(SpringBcryptEncoder.KEY_STRENGTH, String.valueOf(7));
		return createEncoder(props);
	}

	private SpringBcryptEncoder createEncoder(final Properties defaults) {
		final SpringBcryptEncoder encoder = new SpringBcryptEncoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
