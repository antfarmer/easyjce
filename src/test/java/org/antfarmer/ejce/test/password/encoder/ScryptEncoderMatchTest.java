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

import org.antfarmer.ejce.password.encoder.AbstractScryptPasswordEncoder;
import org.antfarmer.ejce.password.encoder.bc.BcScryptEncoder;
import org.antfarmer.ejce.password.encoder.spring.SpringScryptEncoder;
import org.junit.Test;
/**
 * @author Ameer Antar
 */
public class ScryptEncoderMatchTest {

	private static final String TEXT = "bandOgyps";
	private static final int CPU_COST = 1024;

	@Test
	public void testSCrypt() {
		final BcScryptEncoder bcbe = createBcsEncoder(null);
		final SpringScryptEncoder spbe = createSpsEncoder(null);

		final String encB = bcbe.encode(TEXT);
		final String encS = spbe.encode(TEXT);

		System.out.println(encB);
		System.out.println(encS);

		assertTrue(bcbe.matches(TEXT, encB));
		assertTrue(bcbe.matches(TEXT, encS));

		assertTrue(spbe.matches(TEXT, encS));
		assertTrue(spbe.matches(TEXT, encB));
	}


	private BcScryptEncoder createBcsEncoder(final Properties defaults) {
		final BcScryptEncoder encoder = new BcScryptEncoder();
		final Properties props = new Properties(defaults);
		props.setProperty(AbstractScryptPasswordEncoder.KEY_CPU_COST, String.valueOf(CPU_COST));
		encoder.configure(props, null);
		return encoder;
	}

	private SpringScryptEncoder createSpsEncoder(final Properties defaults) {
		final SpringScryptEncoder encoder = new SpringScryptEncoder();
		final Properties props = new Properties(defaults);
		props.setProperty(AbstractScryptPasswordEncoder.KEY_CPU_COST, String.valueOf(CPU_COST));
		encoder.configure(props, null);
		return encoder;
	}

}
