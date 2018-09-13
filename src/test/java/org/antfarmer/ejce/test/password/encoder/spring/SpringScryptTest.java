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
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.antfarmer.ejce.password.encoder.spring.SpringScryptEncoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

/**
 * @author Ameer Antar
 */
public class SpringScryptTest extends AbstractPasswordTest<SpringScryptEncoder> {

	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final int cpuCost = 4096;
		final int memCost = 12;
		final int parallel = 2;
		final int keyLen = 128;
		final int saltLen = 256;
		final Properties props = new Properties();
		props.setProperty(SpringScryptEncoder.KEY_CPU_COST, String.valueOf(cpuCost));
		props.setProperty(SpringScryptEncoder.KEY_MEM_COST, String.valueOf(memCost));
		props.setProperty(SpringScryptEncoder.KEY_PARALLELIZATION, String.valueOf(parallel));
		props.setProperty(SpringScryptEncoder.KEY_KEY_LENGTH, String.valueOf(keyLen));
		props.setProperty(SpringScryptEncoder.KEY_SALT_LENGTH, String.valueOf(saltLen));
		final SpringScryptEncoder encoder = createEncoder(props);

		final SCryptPasswordEncoder pswdEnc = ReflectionUtil.getFieldValue(encoder, "pswdEnc");
		assertEquals(Integer.valueOf(cpuCost), ReflectionUtil.getFieldValue(pswdEnc, "cpuCost"));
		assertEquals(Integer.valueOf(memCost), ReflectionUtil.getFieldValue(pswdEnc, "memoryCost"));
		assertEquals(Integer.valueOf(parallel), ReflectionUtil.getFieldValue(pswdEnc, "parallelization"));
		assertEquals(Integer.valueOf(keyLen), ReflectionUtil.getFieldValue(pswdEnc, "keyLength"));
		assertEquals(Integer.valueOf(saltLen), Integer.valueOf(((BytesKeyGenerator)ReflectionUtil.getFieldValue(pswdEnc, "saltGenerator")).getKeyLength()));

		final String encoded = encoder.encode(PASSWORD);
		assertFalse(PASSWORD.equals(encoded));
		assertTrue(encoder.matches(PASSWORD, encoded));
	}

	@Override
	protected SpringScryptEncoder createEncoder() {
		return createEncoder(null);
	}

	@Override
	protected SpringScryptEncoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(SpringScryptEncoder.KEY_CPU_COST, String.valueOf(2048));
		return createEncoder(props);
	}

	private SpringScryptEncoder createEncoder(final Properties defaults) {
		final SpringScryptEncoder encoder = new SpringScryptEncoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
