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

import org.antfarmer.ejce.password.encoder.AbstractBcryptPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Password encoder using Spring's BCrpyt implementation.
 * @author Ameer Antar
 */
public class SpringBcryptEncoder extends AbstractBcryptPasswordEncoder {

	private BCryptPasswordEncoder pswdEnc;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doConfigure(final Properties parameters, final String prefix) {
		pswdEnc = new BCryptPasswordEncoder(
				parseInt(parameters, prefix, KEY_STRENGTH, DEFAULT_STRENGTH),
				getRandom(parameters, prefix)
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
