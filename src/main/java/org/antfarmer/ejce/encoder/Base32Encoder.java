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
 * Encoder for encoding/decoding bytes and text using the Base-32 format without padding. The
 * encoded results contain only US-ASCII letters and numbers. The character set includes: [A-Z2-7].
 * This format results in a 60% increase in output length at best. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.3
 */
public class Base32Encoder extends AbstractBase32Encoder {

	private static final Base32Encoder instance = new Base32Encoder();

	private Base32Encoder() {
		// singleton
	}

	/**
	 * Returns an instance of a Base32Encoder.
	 * @return an instance of a Base32Encoder
	 */
	public static Base32Encoder getInstance() {
		return instance;
	}

}