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
package org.antfarmer.ejce.util;

/**
 * Utility useful for converting numbers to and from bytes.
 * @author Ameer Antar
 */
public final class ByteUtil {

	private static final long BYTE_BIT_MASK = 0xFF;

	private ByteUtil() {
		// static methods only
	}

	/**
	 * Converts a long to its byte array representation.
	 * @param number the long
	 * @return the number's byte array representation
	 */
	public static byte[] toBytes(final long number) {
		final byte[] bytes = new byte[Long.SIZE / Byte.SIZE];
		int b = 0;
		for (int i=bytes.length-1; i>=0; i--) {
			bytes[b++] = (byte) ((number >> (i * Byte.SIZE)) & BYTE_BIT_MASK);
		}
		return bytes;
	}

	/**
	 * Converts a byte array to a long.
	 * @param bytes the byte array
	 * @return a long represented by the byte array
	 */
	public static long toLong(final byte[] bytes) {
		long num = 0;
		int b = 0;
		for (int i=bytes.length-1; i>=0; i--) {
			final long n = bytes[b++];
			num |= ((n << (i * Byte.SIZE)) & (BYTE_BIT_MASK << (i * Byte.SIZE)));
		}
		return num;
	}

	/**
	 * Converts an integer to its byte array representation.
	 * @param number the integer
	 * @return the number's byte array representation
	 */
	public static byte[] toBytes(final int number) {
		final byte[] bytes = new byte[Integer.SIZE / Byte.SIZE];
		int b = 0;
		for (int i=bytes.length-1; i>=0; i--) {
			bytes[b++] = (byte) ((number >> (i * Byte.SIZE)) & BYTE_BIT_MASK);
		}
		return bytes;
	}

	/**
	 * Converts a byte array to an integer.
	 * @param bytes the byte array
	 * @return an integer represented by the byte array
	 */
	public static int toInt(final byte[] bytes) {
		int num = 0;
		int b = 0;
		for (int i=bytes.length-1; i>=0; i--) {
			final int n = bytes[b++];
			num |= ((n << (i * Byte.SIZE)) & ((int)(BYTE_BIT_MASK << (i * Byte.SIZE))));
		}
		return num;
	}

	/**
	 * Converts a short to its byte array representation.
	 * @param number the short
	 * @return the number's byte array representation
	 */
	public static byte[] toBytes(final short number) {
		final byte[] bytes = new byte[Short.SIZE / Byte.SIZE];
		int b = 0;
		for (int i=bytes.length-1; i>=0; i--) {
			bytes[b++] = (byte) ((number >> (i * Byte.SIZE)) & BYTE_BIT_MASK);
		}
		return bytes;
	}

	/**
	 * Converts a byte array to a short.
	 * @param bytes the byte array
	 * @return a short represented by the byte array
	 */
	public static short toShort(final byte[] bytes) {
		short num = 0;
		int b = 0;
		for (int i=bytes.length-1; i>=0; i--) {
			final short n = bytes[b++];
			num |= ((n << (i * Byte.SIZE)) & ((short)(BYTE_BIT_MASK << (i * Byte.SIZE))));
		}
		return num;
	}

	/**
	 * Converts a double to its byte array representation.
	 * @param number the double
	 * @return the number's byte array representation
	 */
	public static byte[] toBytes(final double number) {
		return toBytes(Double.doubleToRawLongBits(number));
	}

	/**
	 * Converts a byte array to a double.
	 * @param bytes the byte array
	 * @return a double represented by the byte array
	 */
	public static double toDouble(final byte[] bytes) {
		return Double.longBitsToDouble(toLong(bytes));
	}

	/**
	 * Converts a float to its byte array representation.
	 * @param number the float
	 * @return the number's byte array representation
	 */
	public static byte[] toBytes(final float number) {
		return toBytes(Float.floatToRawIntBits(number));
	}

	/**
	 * Converts a byte array to a float.
	 * @param bytes the byte array
	 * @return a float represented by the byte array
	 */
	public static float toFloat(final byte[] bytes) {
		return Float.intBitsToFloat(toInt(bytes));
	}

	/**
	 * Returns a copy of the given byte array.
	 * @param b the original byte array
	 * @return a copy of the given byte array
	 */
	public static byte[] copy(final byte[] b) {
		if (b == null) {
			return null;
		}
		return copy(b, 0, b.length);
	}

	/**
	 * Returns a copy of the given byte array using the given offset and length.
	 * @param b the original byte array
	 * @param offset the initial offset
	 * @param length the length
	 * @return a copy of the given byte array using the given offset and length
	 */
	public static byte[] copy(final byte[] b, final int offset, final int length) {
		if (b == null) {
			return null;
		}
		final byte[] copy = new byte[length];
		if (length > 0) {
			System.arraycopy(b, offset, copy, 0, length);
		}
		return copy;
	}

}
