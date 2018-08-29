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

import java.util.Arrays;

/**
 * Abstract encoder for encoding/decoding bytes and text using the Base-32 format without any numeric characters in the
 * encoded result. The encoded results do not contain any special characters, only US-ASCII letters. The character set
 * includes: [A-Za-f]. This format results in a 60% increase in output length at best. <b>This class is thread-safe.</b>
 * @author Ameer Antar
 * @version 1.2
 */
public abstract class AbstractBase32NonNumericEncoder extends AbstractBase32Encoder {

	/**
	 * Initializes the AbstractBase32NonNumericEncoder.
	 */
	protected AbstractBase32NonNumericEncoder() {
		// setup encode array
		final byte[] encodeArray = getEncodeArray();
		for (int i = 0; i < 26; i++)
			encodeArray[i] = (byte) (i + 65);
		for (int i = 26; i < 32; i++)
			encodeArray[i] = (byte) (i + 71);

		// setup decode array
		final byte[] decodeArray = getDecodeArray();
		Arrays.fill(decodeArray, (byte) -1);
		for (int i = 65; i < 91; i++)
			decodeArray[i] = (byte) (i - 65);
		for (int i = 97; i < 103; i++)
			decodeArray[i] = (byte) (i - 71);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected byte getPaddingChar() {
		return 'x';
	}

}