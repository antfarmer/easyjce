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

import java.security.GeneralSecurityException;
import java.util.Calendar;

import org.antfarmer.ejce.hibernate.EncryptedCalendarType;
import org.antfarmer.ejce.test.hibernate.util.TypeUtil;
import org.junit.Before;
import org.junit.Test;


/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedCalendarTypeTest extends EncryptedCalendarType {

	private static final Calendar TEST_VALUE = Calendar.getInstance();

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 *
	 */
	@Before
	public void init() throws GeneralSecurityException {
		setParameterValues(TypeUtil.prepareTestEncryptor());
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void test() throws GeneralSecurityException {
		final Calendar o = Calendar.getInstance();
		final String enc = encrypt(o);
		final Object dec = decrypt(enc);
		assertEquals(o, dec);
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
