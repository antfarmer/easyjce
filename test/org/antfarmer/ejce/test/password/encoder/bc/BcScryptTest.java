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
import org.antfarmer.ejce.password.encoder.bc.BcScryptEncoder;
import org.antfarmer.ejce.test.password.AbstractPasswordTest;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class BcScryptTest extends AbstractPasswordTest<BcScryptEncoder> {
/*
	private int cpuCost;

	private int memoryCost;

	private int parallelization;

	private int keyLength;

	private int saltLength;

	private int keyLengthBytes;

	private int saltLengthBytes;

	private SecureRandom random;
*/
	@Test
	public void testConfigure() throws NoSuchFieldException, IllegalAccessException {
		final int cpuCost = 8192;
		final int memCost = 13;
		final int parallel = 3;
		final int keyLen = 512;
		final int saltLen = 512;
		final Class<? extends SecureRandom> rc = MyRandom.class;
		final Properties props = new Properties();
		props.setProperty(BcScryptEncoder.KEY_CPU_COST, String.valueOf(cpuCost));
		props.setProperty(BcScryptEncoder.KEY_MEM_COST, String.valueOf(memCost));
		props.setProperty(BcScryptEncoder.KEY_PARALLELIZATION, String.valueOf(parallel));
		props.setProperty(BcScryptEncoder.KEY_KEY_LENGTH, String.valueOf(keyLen));
		props.setProperty(BcScryptEncoder.KEY_SALT_LENGTH, String.valueOf(saltLen));
		props.setProperty(BcBcryptEncoder.KEY_RANDOM, rc.getName());
		final BcScryptEncoder encoder = createEncoder(props);

		assertEquals(Integer.valueOf(cpuCost), ReflectionUtil.getFieldValue(encoder, "cpuCost"));
		assertEquals(Integer.valueOf(memCost), ReflectionUtil.getFieldValue(encoder, "memoryCost"));
		assertEquals(Integer.valueOf(parallel), ReflectionUtil.getFieldValue(encoder, "parallelization"));
		assertEquals(Integer.valueOf(keyLen), ReflectionUtil.getFieldValue(encoder, "keyLength"));
		assertEquals(Integer.valueOf(saltLen), ReflectionUtil.getFieldValue(encoder, "saltLength"));
		assertSame(rc, ReflectionUtil.getFieldValue(encoder, "random").getClass());

		final String encoded = encoder.encode(PASSWORD);
		assertFalse(PASSWORD.equals(encoded));
		assertTrue(encoder.matches(PASSWORD, encoded));
	}

	@Override
	protected BcScryptEncoder createEncoder() {
		return createEncoder(null);
	}

	@Override
	protected BcScryptEncoder createFastEncoder() {
		final Properties props = new Properties();
		props.setProperty(BcScryptEncoder.KEY_CPU_COST, String.valueOf(2048));
		return createEncoder(props);
	}

	private BcScryptEncoder createEncoder(final Properties defaults) {
		final BcScryptEncoder encoder = new BcScryptEncoder();
		final Properties props = new Properties(defaults);
		encoder.configure(props, null);
		return encoder;
	}

}
