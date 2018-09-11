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

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Abstract encoder for encoding/decoding bytes and text using the Base-32 format. The
 * encoded results contain only US-ASCII letters and numbers. The character set includes: [A-Z2-7].
 * This format results in a 60% increase in output length at best. <b>This class is thread-safe.</b>
 *
 * @author Ameer Antar
 * @version 1.2
 */
public abstract class AbstractBase32Encoder implements TextEncoder {

	private static final Pattern WHITE_SPACE_PATTERN = Pattern.compile("\\s");

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	/**
	 * Array used for encoding text to Base32.
	 */
	private final byte[] encodeArray = new byte[32];

	/**
	 * Array used for decoding text from Base32.
	 */
	private final byte[] decodeArray = new byte[121];

	/**
	 * Character to be used for padding Base32 encoded text.
	 */
	private final byte paddingChar;

	/**
	 * Indicates whether padding should be used for encoding/decoding data.
	 */
	private final boolean usePadding;

	/**
	 * Initializes the AbstractBase32Encoder.
	 */
	protected AbstractBase32Encoder() {
		// setup encode array
		for (int i = 0; i < 26; i++)
			encodeArray[i] = (byte) (i + 65);
		for (int i = 26; i < 32; i++)
			encodeArray[i] = (byte) (i + 24);

		// setup decode array
		Arrays.fill(decodeArray, (byte) -1);
		for (int i = 65; i < 91; i++)
			decodeArray[i] = (byte) (i - 65);
		for (int i = 50; i < 56; i++)
			decodeArray[i] = (byte) (i - 24);
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
		final int remainder = originalSize % 5;
		if (remainder == 0) {
			encodedBytes = new byte[((originalSize << 3) / 5)];
		}
		else {
			if (!usePadding) {
				encodedBytes = new byte[(int) Math.ceil((originalSize << 3) / 5.0)];
			}
			else {
				encodedBytes = new byte[(((originalSize + 5 - remainder) << 3) / 5)];
			}
			originalSize -= remainder;
		}

		int k = 0;
		for (i = 0; i < originalSize; i += 5) {
			encodedBytes[k] = encodeArray[chars[i] >> 3];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x07) << 2) + (chars[i + 1] >> 6)];
			encodedBytes[k + 2] = encodeArray[((chars[i + 1] & 0x3F) >> 1)];
			encodedBytes[k + 3] = encodeArray[((chars[i + 1] & 0x01) << 4) + (chars[i + 2] >> 4)];
			encodedBytes[k + 4] = encodeArray[((chars[i + 2] & 0x0F) << 1) + (chars[i + 3] >> 7)];
			encodedBytes[k + 5] = encodeArray[((chars[i + 3] & 0x7F) >> 2)];
			encodedBytes[k + 6] = encodeArray[((chars[i + 3] & 0x03) << 3) + (chars[i + 4] >> 5)];
			encodedBytes[k + 7] = encodeArray[(chars[i + 4] & 0x1F)];
			k += 8;
		}

		if (remainder == 1) {
			// 1 extra byte
			encodedBytes[k] = encodeArray[chars[i] >> 3];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x07) << 2)];
			if (usePadding) {
				encodedBytes[k + 2] = paddingChar;
				encodedBytes[k + 3] = paddingChar;
				encodedBytes[k + 4] = paddingChar;
				encodedBytes[k + 5] = paddingChar;
				encodedBytes[k + 6] = paddingChar;
				encodedBytes[k + 7] = paddingChar;
			}
		}
		else if (remainder == 2) {
			// 2 extra bytes
			encodedBytes[k] = encodeArray[chars[i] >> 3];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x07) << 2) + (chars[i + 1] >> 6)];
			encodedBytes[k + 2] = encodeArray[((chars[i + 1] & 0x3F) >> 1)];
			encodedBytes[k + 3] = encodeArray[((chars[i + 1] & 0x01) << 4)];
			if (usePadding) {
				encodedBytes[k + 4] = paddingChar;
				encodedBytes[k + 5] = paddingChar;
				encodedBytes[k + 6] = paddingChar;
				encodedBytes[k + 7] = paddingChar;
			}
		}
		else if (remainder == 3) {
			// 3 extra bytes
			encodedBytes[k] = encodeArray[chars[i] >> 3];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x07) << 2) + (chars[i + 1] >> 6)];
			encodedBytes[k + 2] = encodeArray[((chars[i + 1] & 0x3F) >> 1)];
			encodedBytes[k + 3] = encodeArray[((chars[i + 1] & 0x01) << 4) + (chars[i + 2] >> 4)];
			encodedBytes[k + 4] = encodeArray[((chars[i + 2] & 0x0F) << 1)];
			if (usePadding) {
				encodedBytes[k + 5] = paddingChar;
				encodedBytes[k + 6] = paddingChar;
				encodedBytes[k + 7] = paddingChar;
			}
		}
		else if (remainder == 4) {
			// 4 extra bytes
			encodedBytes[k] = encodeArray[chars[i] >> 3];
			encodedBytes[k + 1] = encodeArray[((chars[i] & 0x07) << 2) + (chars[i + 1] >> 6)];
			encodedBytes[k + 2] = encodeArray[((chars[i + 1] & 0x3F) >> 1)];
			encodedBytes[k + 3] = encodeArray[((chars[i + 1] & 0x01) << 4) + (chars[i + 2] >> 4)];
			encodedBytes[k + 4] = encodeArray[((chars[i + 2] & 0x0F) << 1) + (chars[i + 3] >> 7)];
			encodedBytes[k + 5] = encodeArray[((chars[i + 3] & 0x7F) >> 2)];
			encodedBytes[k + 6] = encodeArray[((chars[i + 3] & 0x03) << 3)];
			if (usePadding) {
				encodedBytes[k + 7] = paddingChar;
			}
		}

		return new String(encodedBytes, DEFAULT_CHARSET);
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
		if (usePadding && originalSize % 8 != 0) {
			throw new IllegalArgumentException("Encoded string does not match Base-32 format with padding.");
		}

		int newSize = (originalSize * 5) >> 3;
		int remainder = 8;
		if (usePadding) {
			final int p = encodedText.indexOf(paddingChar);
			if (p > 0) {
				newSize -= Math.round((originalSize - p) * 5 / 8.0);
				remainder = p % 8;
			}
		}
		else {
			final int m = originalSize % 8;
			if (m > 0)
				remainder = m;
		}
		final byte[] byteArr = new byte[newSize];
		originalSize -= 8;

		int i, j = 0;
		final byte[] hexArr = new byte[8];
		for (i = 0; i < originalSize; i += 8) {
			for (int k = 0; k < 8; k++)
				hexArr[k] = getDecodedValue(encodedText.charAt(i + k));
			byteArr[j] = (byte) (hexArr[0] << 3);
			byteArr[j] += (hexArr[1] >> 2);
			byteArr[j + 1] = (byte) (hexArr[1] << 6);
			byteArr[j + 1] += (hexArr[2] << 1);
			byteArr[j + 1] += (hexArr[3] >> 4);
			byteArr[j + 2] = (byte) (hexArr[3] << 4);
			byteArr[j + 2] += (hexArr[4] >> 1);
			byteArr[j + 3] = (byte) (hexArr[4] << 7);
			byteArr[j + 3] += (hexArr[5] << 2);
			byteArr[j + 3] += (hexArr[6] >> 3);
			byteArr[j + 4] = (byte) (hexArr[6] << 5);
			byteArr[j + 4] += hexArr[7];
			j += 5;
		}

		for (int k = 0; k < remainder; k++)
			hexArr[k] = getDecodedValue(encodedText.charAt(i + k));
		byteArr[j] = (byte) (hexArr[0] << 3);
		byteArr[j] += (hexArr[1] >> 2);
		if (newSize > j + 1) {
			byteArr[j + 1] = (byte) (hexArr[1] << 6);
			byteArr[j + 1] += (hexArr[2] << 1);
			byteArr[j + 1] += (hexArr[3] >> 4);
		}
		if (newSize > j + 2) {
			byteArr[j + 2] = (byte) (hexArr[3] << 4);
			byteArr[j + 2] += (hexArr[4] >> 1);
		}
		if (newSize > j + 3) {
			byteArr[j + 3] = (byte) (hexArr[4] << 7);
			byteArr[j + 3] += (hexArr[5] << 2);
			byteArr[j + 3] += (hexArr[6] >> 3);
		}
		if (newSize > j + 4) {
			byteArr[j + 4] = (byte) (hexArr[6] << 5);
			byteArr[j + 4] += hexArr[7];
		}

		return byteArr;
	}

	private byte getDecodedValue(final int ch) {
		if (ch < 0 || ch >= decodeArray.length || decodeArray[ch] == -1) {
			throw new IllegalArgumentException("Base-32 encoded string contained invalid character: " + (char)(ch));
		}
		return decodeArray[ch];
	}

}