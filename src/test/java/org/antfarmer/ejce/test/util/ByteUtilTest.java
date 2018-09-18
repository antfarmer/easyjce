/*
 * Copyright 2018 Ameer Antar.
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
package org.antfarmer.ejce.test.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

import org.antfarmer.ejce.test.AbstractTest;
import org.antfarmer.ejce.util.ByteUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class ByteUtilTest extends AbstractTest {

	@Test
	public void testByteConversion() {
		byte[] b;

		final long l = Long.MAX_VALUE;
		b = ByteUtil.toBytes(l);
		assertEquals(Long.BYTES, b.length);
		assertEquals(l, ByteUtil.toLong(b));

		final int i = Integer.MAX_VALUE;
		b = ByteUtil.toBytes(i);
		assertEquals(Integer.BYTES, b.length);
		assertEquals(i, ByteUtil.toInt(b));

		final short s = Short.MAX_VALUE;
		b = ByteUtil.toBytes(s);
		assertEquals(Short.BYTES, b.length);
		assertEquals(s, ByteUtil.toShort(b));

		final double d = Double.MAX_VALUE;
		b = ByteUtil.toBytes(d);
		assertEquals(Double.BYTES, b.length);
		assertEquals(d, ByteUtil.toDouble(b), 0.001);

		final float f = Float.MAX_VALUE;
		b = ByteUtil.toBytes(f);
		assertEquals(Float.BYTES, b.length);
		assertEquals(f, ByteUtil.toFloat(b), 0.001f);
	}

	@Test
	public void testByteCopy() {
		byte[] b, copy;

		assertNull(ByteUtil.copy(null));

		b = new byte[0];
		copy = ByteUtil.copy(b);
		assertNotNull(copy);
		assertNotSame(copy, b);
		assertEquals(b.length, copy.length);

		b = new byte[100];
		RANDOM.nextBytes(b);
		copy = ByteUtil.copy(b);
		assertNotNull(copy);
		assertNotSame(copy, b);
		assertEquals(b.length, copy.length);
		assertArrayEquals(copy, b);


		final int off = 9;
		final int len = 55;
		assertNull(ByteUtil.copy(null, off, len));

		b = new byte[0];
		copy = ByteUtil.copy(b, off, 0);
		assertNotNull(copy);
		assertNotSame(copy, b);
		assertEquals(b.length, copy.length);

		b = new byte[100];
		RANDOM.nextBytes(b);
		copy = ByteUtil.copy(b, off, len);
		assertNotNull(copy);
		assertNotSame(copy, b);
		assertEquals(len, copy.length);
		assertArrayEquals(Arrays.copyOfRange(b, off, off + len), copy);
	}

	@Test(expected = ArrayIndexOutOfBoundsException.class)
	public void testIllegalByteCopy() {
		final byte[] b = new byte[0];
		ByteUtil.copy(b, 1, 50);
	}

	@Test
	public void testByteClear() {
		final byte[] b = new byte[25];
		final byte[] z = new byte[b.length];
		Arrays.fill(b, (byte) 4);

		ByteUtil.clear((byte[]) null);
		ByteUtil.clear(b);
		assertArrayEquals(z, b);
	}

	@Test
	public void testCharClear() {
		final char[] b = new char[25];
		final char[] z = new char[b.length];
		Arrays.fill(b, (char) 4);

		ByteUtil.clear((char[]) null);
		ByteUtil.clear(b);
		assertArrayEquals(z, b);
	}

}
