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
 * Encoder for encoding/decoding bytes and text using the Base-32 format with padding but without
 * any numeric characters in the encoded result. The encoded results do not contain any special
 * characters, only US-ASCII letters. The character set includes: [A-Za-fx]. This format results in
 * a 60% increase in output length at best. Use of padding increases the output to input length
 * ratio, especially for short byte arrays. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.3
 */
public class Base32NonNumericPaddedEncoder extends AbstractBase32NonNumericEncoder {

	private static final Base32NonNumericPaddedEncoder instance = new Base32NonNumericPaddedEncoder();

	private Base32NonNumericPaddedEncoder() {
		// singleton
	}

	/**
	 * Returns an instance of a Base32NonNumericPaddedEncoder.
	 * @return an instance of a Base32NonNumericPaddedEncoder
	 */
	public static Base32NonNumericPaddedEncoder getInstance() {
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
