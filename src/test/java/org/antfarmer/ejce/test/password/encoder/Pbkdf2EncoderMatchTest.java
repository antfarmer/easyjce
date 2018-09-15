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

import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.antfarmer.ejce.password.encoder.AbstractPbkdf2PasswordEncoder;
import org.antfarmer.ejce.password.encoder.Pbkdf2Encoder;
import org.antfarmer.ejce.password.encoder.spring.SpringPbkdf2Encoder;
import org.junit.Test;
/**
 * @author Ameer Antar
 */
public class Pbkdf2EncoderMatchTest {

	private static final String TEXT = "bandOgyps";
	private static final int ITERATIONS = 2000;

	@Test
	public void testPBKDF2() {
		final Pbkdf2Encoder bcbe = createBcsEncoder(null);
		final SpringPbkdf2Encoder spbe = createSpsEncoder(null);

		final String encB = bcbe.encode(TEXT);
		final String encS = spbe.encode(TEXT);

		System.out.println(encB);
		System.out.println(encS);

		assertTrue(bcbe.matches(TEXT, encB));
		assertTrue(bcbe.matches(TEXT, encS));

		assertTrue(spbe.matches(TEXT, encS));
		assertTrue(spbe.matches(TEXT, encB));
	}


	private Pbkdf2Encoder createBcsEncoder(final Properties defaults) {
		final Pbkdf2Encoder encoder = new Pbkdf2Encoder();
		final Properties props = new Properties(defaults);
		props.setProperty(AbstractPbkdf2PasswordEncoder.KEY_ITERATIONS, String.valueOf(ITERATIONS));
		encoder.configure(props, null);
		return encoder;
	}

	private SpringPbkdf2Encoder createSpsEncoder(final Properties defaults) {
		final SpringPbkdf2Encoder encoder = new SpringPbkdf2Encoder();
		final Properties props = new Properties(defaults);
		props.setProperty(AbstractPbkdf2PasswordEncoder.KEY_ITERATIONS, String.valueOf(ITERATIONS));
		encoder.configure(props, null);
		return encoder;
	}

}
