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
package org.antfarmer.ejce.test.hibernate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.sql.Types;

import org.antfarmer.ejce.hibernate.EncryptedStringType;
import org.antfarmer.ejce.test.hibernate.util.TypeUtil;
import org.junit.Before;
import org.junit.Test;


/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedStringTypeTest extends EncryptedStringType {

	private static final String TEST_VALUE = "BingGingGingGing";

	private static final Charset CHARSET = Charset.forName("UTF-16");

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 *
	 */
	@Before
	public void init() throws GeneralSecurityException {
		setParameterValues(TypeUtil.prepareTestEncryptor(CHARSET));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void test() throws GeneralSecurityException {
		final String o = "seCRet";
		final String enc = encrypt(o);
		final Object dec = decrypt(enc);
		assertEquals(o, dec);
	}

	@Test
	public void testUnicode() throws GeneralSecurityException {
		final String o = "\u0627\u0645\u064a\u0631";

		// can run with '-Dfile.encoding=ISO-8859-1'
		System.out.println(Charset.defaultCharset());
		System.out.println(o);

		final String enc = encrypt(o);
		final Object dec = decrypt(enc);
		System.out.println(dec);
		assertEquals(o, dec);
	}

	@Test
	public void testTypeMethods() throws GeneralSecurityException {

		// assemble
		String o = null;
		assertNull(assemble(o, this));
		o = new String();
		assertSame(o, assemble(o, this));

		// deepCopy
		assertSame(o, deepCopy(o));

		// disassemble
		o = null;
		assertNull(disassemble(o));
		o = new String();
		assertSame(o, disassemble(o));

		// equals
		assertTrue(equals(null, null));
		assertFalse(equals(o, null));
		assertFalse(equals(null, o));
		assertTrue(equals(o, o));
		assertTrue(equals(o, new String()));
		assertTrue(equals(new String(), o));

		// hashCode
		assertSame(o.hashCode(), hashCode(o));

		// isMutable
		assertFalse(isMutable());

		// replace
		assertSame(o, replace(o, "other", this));

		// sqlTypes
		assertArrayEquals(new int[] {Types.VARCHAR}, sqlTypes());

		// returnedClass
		assertSame(String.class, returnedClass());
	}

	@Test
	public void testThreadSafety() throws Throwable {
		final int num = 25;
		final EncryptThread[] threads = new EncryptThread[num];
		for (int i=0; i<num; i++) {
			threads[i] = new EncryptThread();
			threads[i].start();
		}
		for (int i=0; i<num; i++) {
			threads[i].join();
			if (threads[i].exception != null) {
				throw threads[i].exception;
			}
		}
	}

	private class EncryptThread extends Thread {
		private Throwable exception;

		/**
		 * {@inheritDoc}
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<50; i++) {
					final String enc = encrypt(TEST_VALUE);
					assertEquals(TEST_VALUE, decrypt(enc));
				}
			}
			catch (final Throwable e) {
				exception = e;
				e.printStackTrace();
			}
		}

	}

}
