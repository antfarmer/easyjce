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
 * Encoder for encoding/decoding bytes and text using the Base-64 format without padding which is
 * safe to use in URL's. The character set includes: [-.A-Za-z0-9]. This format results in a 33%
 * increase in output length at best. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.3
 */
public class Base64UrlEncoder extends AbstractBase64UrlEncoder {

	private static final Base64UrlEncoder instance = new Base64UrlEncoder();

	private Base64UrlEncoder() {
		// singleton
	}

	/**
	 * Returns an instance of a Base64UrlEncoder.
	 * @return an instance of a Base64UrlEncoder
	 */
	public static Base64UrlEncoder getInstance() {
		return instance;
	}

}
