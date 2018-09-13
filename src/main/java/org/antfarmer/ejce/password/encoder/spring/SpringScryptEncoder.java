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
package org.antfarmer.ejce.password.encoder.spring;

import java.util.Properties;

import org.antfarmer.ejce.password.encoder.AbstractScryptPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

/**
 * Password encoder using Spring's SCrpyt implementation.
 * @author Ameer Antar
 */
public class SpringScryptEncoder extends AbstractScryptPasswordEncoder {

	private SCryptPasswordEncoder pswdEnc;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doConfigure(final Properties parameters, final String prefix) {
		pswdEnc = new SCryptPasswordEncoder(
				parseInt(parameters, prefix, KEY_CPU_COST, DEFAULT_CPU_COST),
				parseInt(parameters, prefix, KEY_MEM_COST, DEFAULT_MEM_COST),
				parseInt(parameters, prefix, KEY_PARALLELIZATION, DEFAULT_PARALLELIZATION),
				parseInt(parameters, prefix, KEY_KEY_LENGTH, DEFAULT_KEY_LENGTH),
				parseInt(parameters, prefix, KEY_SALT_LENGTH, DEFAULT_SALT_LENGTH)
		);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String doEncode(final CharSequence rawPassword) {
		return pswdEnc.encode(rawPassword);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isMatch(final CharSequence rawPassword, final String encodedPassword) {
		return pswdEnc.matches(rawPassword, encodedPassword);
	}

}
