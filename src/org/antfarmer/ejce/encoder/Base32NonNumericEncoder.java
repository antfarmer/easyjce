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
 * Encoder for encoding/decoding bytes and text using the Base-32 format without any numeric
 * characters or padding in the encoded result. The encoded results do not contain any special
 * characters, only US-ASCII letters. The character set includes: [A-Za-f]. This format results in a
 * 60% increase in output length at best. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.3
 */
public class Base32NonNumericEncoder extends AbstractBase32NonNumericEncoder {

	private static final Base32NonNumericEncoder instance = new Base32NonNumericEncoder();

	private Base32NonNumericEncoder() {
		// singleton
	}

	/**
	 * Returns an instance of a Base32NonNumericEncoder.
	 * @return an instance of a Base32NonNumericEncoder
	 */
	public static Base32NonNumericEncoder getInstance() {
		return instance;
	}

}