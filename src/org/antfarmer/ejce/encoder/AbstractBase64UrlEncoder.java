/*
 * Copyright 2006 Ameer Antar.
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
 * Abstract encoder for encoding/decoding bytes and text using the Base-64 format which is
 * safe to use in URL's. The character set includes: [-.A-Za-z0-9]. This format results in a 33%
 * increase in output length at best. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.3
 */
public abstract class AbstractBase64UrlEncoder extends AbstractBase64Encoder {

	/**
	 * Initializes the AbstractBase64UrlEncoder.
	 */
	protected AbstractBase64UrlEncoder() {
		// setup encode array
		final byte[] encodeArray = getEncodeArray();
		encodeArray[62] = '-';
		encodeArray[63] = '.';

		// setup decode array
		final byte[] decodeArray = getDecodeArray();
		decodeArray['+'] = -1;
		decodeArray['/'] = -1;
		decodeArray['-'] = 62;
		decodeArray['.'] = 63;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected byte getPaddingChar() {
		return '_';
	}

}
