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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.antfarmer.ejce.password.encoder.AbstractBcryptPasswordEncoder;
import org.antfarmer.ejce.password.encoder.bc.BcBcryptEncoder;
import org.antfarmer.ejce.password.encoder.spring.SpringBcryptEncoder;
import org.junit.Test;
/**
 * @author Ameer Antar
 */
public class BcryptEncoderMatchTest {

	private static final String TEXT = "bandOgyps";
	private static final int STRENGTH = 7;

	@Test
	public void testBCrypt() {
		final BcBcryptEncoder bcbe = createBcbEncoder(null);
		final SpringBcryptEncoder spbe = createSpbEncoder(null);
		final Properties props = new Properties();
		props.setProperty(BcBcryptEncoder.KEY_VERSION, "2a");
		final BcBcryptEncoder bcbeV2a = createBcbEncoder(props);

		final String encB = bcbe.encode(TEXT);
		final String encS = spbe.encode(TEXT);
		final String encBV2a = bcbeV2a.encode(TEXT);

		System.out.println(encB);
		System.out.println(encS);
		System.out.println(encBV2a);

		assertTrue(bcbe.matches(TEXT, encB));
		assertTrue(bcbe.matches(TEXT, encS));
		assertTrue(bcbe.matches(TEXT, encBV2a));

		assertTrue(spbe.matches(TEXT, encS));
		assertFalse(spbe.matches(TEXT, encB));
		assertTrue(spbe.matches(TEXT, encBV2a));

		assertTrue(bcbeV2a.matches(TEXT, encB));
		assertTrue(bcbeV2a.matches(TEXT, encS));
		assertTrue(bcbeV2a.matches(TEXT, encBV2a));
	}


	private BcBcryptEncoder createBcbEncoder(final Properties defaults) {
		final BcBcryptEncoder encoder = new BcBcryptEncoder();
		final Properties props = new Properties(defaults);
		props.setProperty(AbstractBcryptPasswordEncoder.KEY_STRENGTH, String.valueOf(STRENGTH));
		encoder.configure(props, null);
		return encoder;
	}

	private SpringBcryptEncoder createSpbEncoder(final Properties defaults) {
		final SpringBcryptEncoder encoder = new SpringBcryptEncoder();
		final Properties props = new Properties(defaults);
		props.setProperty(AbstractBcryptPasswordEncoder.KEY_STRENGTH, String.valueOf(STRENGTH));
		encoder.configure(props, null);
		return encoder;
	}

}
