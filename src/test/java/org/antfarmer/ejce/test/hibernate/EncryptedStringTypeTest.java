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

import static org.junit.Assert.assertEquals;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

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
	 * @throws GeneralSecurityException
	 *
	 */
	@Before
	public void init() throws GeneralSecurityException {
		setParameterValues(TypeUtil.prepareTestEncryptor(CHARSET));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void test() throws GeneralSecurityException {
		final String o = "seCRet";
		final String enc = encrypt(o);
		final Object dec = decrypt(enc);
		assertEquals(o, dec);
	}

	/**
	 *
	 */
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

	/**
	 *
	 */
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
