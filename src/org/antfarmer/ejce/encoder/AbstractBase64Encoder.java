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
import java.util.regex.Pattern;

/**
 * Abstract encoder for encoding/decoding bytes and text using the Base-64 format. The character set includes:
 * [A-Za-z0-9+/]. This format results in a 33% increase in output length at best. <b>This class is thread-safe.</b>
 * @author Ameer Antar
 * @version 1.3
 */
public abstract class AbstractBase64Encoder implements TextEncoder {

	private static final Pattern WHITE_SPACE_PATTERN = Pattern.compile("\\s");

	/**
	 * Array used for encoding text to Base64.
	 */
	private final byte[] encodeArray = new byte[64];

	/**
	 * Array used for decoding text from Base64.
	 */
	private final byte[] decodeArray = new byte[123];

	/**
	 * Character to be used for padding Base64 encoded text.
	 */
	private final byte paddingChar;

	/**
	 * Indicates whether padding should be used for encoding/decoding data.
	 */
	private final boolean usePadding;

	/**
	 * Initializes the AbstractBase64Encoder.
	 */
	protected AbstractBase64Encoder() {
		// setup encode array
		for (int i = 0; i < 26; i++)
			encodeArray[i] = (byte) (i + 65);
		for (int i = 26; i < 52; i++)
			encodeArray[i] = (byte) (i + 71);
		for (int i = 52; i < 62; i++)
			encodeArray[i] = (byte) (i - 4);
		encodeArray[62] = '+';
		encodeArray[63] = '/';

		// setup decode array
		Arrays.fill(decodeArray, (byte) -1);
		decodeArray['+'] = 62;
		decodeArray['/'] = 63;
		for (int i = 48; i < 58; i++)
			decodeArray[i] = (byte) (i + 4);
		for (int i = 65; i < 91; i++)
			decodeArray[i] = (byte) (i - 65);
		for (int i = 97; i < 123; i++)
			decodeArray[i] = (byte) (i - 71);

		paddingChar = getPaddingChar();
		usePadding = isUsePadding();
	}

	/**
	 * Returns the encodeArray.
	 * @return the encodeArray
	 */
	protected final byte[] getEncodeArray() {
		return encodeArray;
	}

	/**
	 * Returns the decodeArray.
	 * @return the decodeArray
	 */
	protected final byte[] getDecodeArray() {
		return decodeArray;
	}

	/**
	 * Returns the padding character.
	 * @return the padding character
	 */
	protected byte getPaddingChar() {
		return '=';
	}

	/**
	 * Returns true if this encoder uses padding.
	 * @return true if this encoder uses padding; false otherwise
	 */
	protected boolean isUsePadding() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String encode(final byte[] bytes) {
		if (bytes == null)
			return null;

		int originalSize = bytes.length;
		if (originalSize < 1) {
			return "";
		}

		int i;
		// convert bytes to unsigned chars
		final char[] chars = new char[originalSize];
		for (i = 0; i < originalSize; i++) {
			if (bytes[i] < 0)
				chars[i] = (char) (bytes[i] + 256);
			else
				chars[i] = (char) bytes[i];
		}

		byte[] encodedBytes;
		final int remainder = originalSize % 3;
		if (remainder == 0)
			encodedBytes = new byte[((originalSize << 2) / 3)];
		else {
			if (!usePadding) {
				encodedBytes = new byte[(int) Math.ceil((originalSize << 2) / 3.0)];
			}
			else {
				encodedBytes = new byte[(((originalSize + 3 - remainder) << 2) / 3)];
			}
			originalSize -= remainder;
		}

		int k = 0;
		for (i = 0; i < originalSize; i += 3) {
			encodedBytes[k] = encodeArray[chars[i] >> 2];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x03) << 4) + (chars[i + 1] >> 4)];
			encodedBytes[k + 2] = encodeArray[((chars[i + 1] & 0x0F) << 2) + (chars[i + 2] >> 6)];
			encodedBytes[k + 3] = encodeArray[chars[i + 2] & 0x3F];
			k += 4;
		}

		if (remainder == 1) {
			// 1 extra byte
			encodedBytes[k] = encodeArray[chars[i] >> 2];
			encodedBytes[k + 1] = encodeArray[(chars[i] & 0x03) << 4];
			if (usePadding) {
				encodedBytes[k + 2] = paddingChar;
				encodedBytes[k + 3] = paddingChar;
			}
		}
		else if (remainder == 2) {
			// 2 extra bytes
			encodedBytes[k] = encodeArray[chars[i] >> 2];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x03) << 4) + (chars[i + 1] >> 4)];
			encodedBytes[k + 2] = encodeArray[((chars[i + 1] & 0x0F) << 2)];
			if (usePadding) {
				encodedBytes[k + 3] = paddingChar;
			}
		}

		return new String(encodedBytes);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] decode(final String text) {
		if (text == null)
			return null;

		// cleanup input string
		final String encodedText = WHITE_SPACE_PATTERN.matcher(text).replaceAll("");
		int originalSize = encodedText.length();
		if (originalSize < 1) {
			return new byte[0];
		}
		if (usePadding && originalSize % 4 != 0) {
			throw new IllegalArgumentException(
					"Encoded string does not match Base-64 format with padding.");
		}

		int newSize = (originalSize * 3) >> 2;
		int remainder = 4;
		if (usePadding) {
			final int p = encodedText.indexOf(paddingChar);
			if (p > 0) {
				newSize -= originalSize - p;
				remainder = p % 4;
			}
		}
		else {
			final int m = originalSize % 4;
			if (m > 0)
				remainder = m;
		}
		final byte[] byteArr = new byte[newSize];
		originalSize -= 4;

		int i, j = 0;
		final byte[] hexArr = new byte[4];
		for (i = 0; i < originalSize; i += 4) {
			for (int k = 0; k < 4; k++)
				hexArr[k] = getDecodedValue(encodedText.charAt(i + k));
			byteArr[j] = (byte) (hexArr[0] << 2);
			byteArr[j] += (hexArr[1] >> 4);
			byteArr[j + 1] = (byte) (hexArr[1] << 4);
			byteArr[j + 1] += (hexArr[2] >> 2);
			byteArr[j + 2] = (byte) (hexArr[2] << 6);
			byteArr[j + 2] += hexArr[3];
			j += 3;
		}

		for (int k = 0; k < remainder; k++)
			hexArr[k] = getDecodedValue(encodedText.charAt(i + k));
		byteArr[j] = (byte) (hexArr[0] << 2);
		byteArr[j] += (hexArr[1] >> 4);
		if (newSize > j + 1) {
			byteArr[j + 1] = (byte) (hexArr[1] << 4);
			byteArr[j + 1] += (hexArr[2] >> 2);
		}
		if (newSize > j + 2) {
			byteArr[j + 2] = (byte) (hexArr[2] << 6);
			byteArr[j + 2] += hexArr[3];
		}

		return byteArr;
	}

	private byte getDecodedValue(final int ch) {
		if (ch < 0 || ch >= decodeArray.length || decodeArray[ch] == -1) {
			throw new IllegalArgumentException("Base-64 encoded string contained invalid character: " + (char)(ch));
		}
		return decodeArray[ch];
	}

}