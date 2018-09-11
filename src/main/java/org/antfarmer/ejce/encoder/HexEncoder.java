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
 * Encoder for encoding/decoding bytes and text using the hexadecimal (Base-16) format. This format
 * results in a 100% increase in output length. The character set includes: [A-F0-9]. <b>This class
 * is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.1
 */
public class HexEncoder implements TextEncoder {

	/**
	 * Array of characters used to represent a number in base-16.
	 */
	private final char[] encodeArray = new char[16];

	/**
	 * Array of values used to decode Hex-encoded values.
	 */
	private final byte[] decodeArray = new byte[71];

	private static final int STRING_BUFF_CAPACITY_OFFSET = 5;

	private static final HexEncoder instance = new HexEncoder();

	/**
	 * Initializes the HexEncoder.
	 */
	protected HexEncoder() {
		for (int i=0; i<10; i++) {
			encodeArray[i] = (char) (0x30 + i);
		}
		for (int i=0; i<6; i++) {
			encodeArray[i+10] = (char) (0x41 + i);
		}
		// setup decode array
		Arrays.fill(decodeArray, (byte) -1);
		for (int i=0; i<10; i++) {
			decodeArray[i+48] = (byte) i;
		}
		for (int i=0; i<6; i++) {
			decodeArray[i+65] = (byte) (i + 10);
		}
	}

	/**
	 * Returns an instance of a HexEncoder.
	 * @return an instance of a HexEncoder
	 */
	public static HexEncoder getInstance() {
		return instance;
	}

	/**
	 * {@inheritDoc}
	 */
	public String encode(final byte[] bytes) {
		if (bytes == null) {
			return null;
		}
		int i;
		final int imax = bytes.length;
		final StringBuilder buff = new StringBuilder((imax << 1) + STRING_BUFF_CAPACITY_OFFSET);
		for (i = 0; i < imax; i++) {
			final int b = bytes[i] & 0xFF;
			buff.append(encodeArray[b >> 4]);
			buff.append(encodeArray[b & 0x0F]);
		}
		return buff.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] decode(final String text) {
		if (text == null) {
			return null;
		}
		int i;
		final int imax = text.length();
		int j = 0;
		if (imax % 2 != 0) {
			throw new IllegalArgumentException(
					"Hex encoded string does not contain even number of characters.");
		}
		final byte[] bytes = new byte[imax / 2];
		for (i = 0; i < imax; i += 2) {
			byte b = (byte) (getDecodedValue(text.charAt(i)) << 4);
			b += getDecodedValue(text.charAt(i + 1));
			bytes[j++] = b;
		}
		return bytes;
	}

	private byte getDecodedValue(final int ch) {
		if (ch < 0 || ch >= decodeArray.length || decodeArray[ch] == -1) {
			throw new IllegalArgumentException("Hex encoded string contained invalid character: " + (char)(ch));
		}
		return decodeArray[ch];
	}

}
