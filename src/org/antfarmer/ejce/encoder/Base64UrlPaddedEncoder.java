/*
 * Copyright 2006-2009 the original author or authors.
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
package org.antfarmer.ejce.encoder;

/**
 * Encoder for encoding/decoding bytes and text using the Base-64 format with padding which is safe
 * to use in URL's. The character set includes: [-._A-Za-z0-9]. This format results in a 33%
 * increase in output length at best. Use of padding increases the output to input length ratio,
 * especially for short byte arrays. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.2
 */
public class Base64UrlPaddedEncoder extends AbstractBase64UrlEncoder {

	private static final Base64UrlPaddedEncoder instance = new Base64UrlPaddedEncoder();

	private Base64UrlPaddedEncoder() {
		// singleton
	}

	/**
	 * Returns an instance of a Base64UrlPaddedEncoder.
	 * @return an instance of a Base64UrlPaddedEncoder
	 */
	public static Base64UrlPaddedEncoder getInstance() {
		return instance;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected boolean isUsePadding() {
		return true;
	}

}
