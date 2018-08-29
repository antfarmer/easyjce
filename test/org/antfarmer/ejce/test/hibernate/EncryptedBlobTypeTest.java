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
package org.antfarmer.ejce.test.hibernate;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Random;

import org.antfarmer.ejce.hibernate.EncryptedBlobType;
import org.antfarmer.ejce.test.hibernate.util.TypeUtil;
import org.antfarmer.ejce.util.StreamUtil;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedBlobTypeTest extends EncryptedBlobType {

	private static final Charset CHARSET = Charset.forName("UTF-16");
	private static final byte[] TEST_VALUE = new byte[1000];
	private static final Random random = new Random();

	static {
		random.nextBytes(TEST_VALUE);
	}

	// TODO test lobToStream, createLob, functionally

	/**
	 * @throws GeneralSecurityException
	 */
	@Before
	public void init() throws GeneralSecurityException {
		setParameterValues(TypeUtil.prepareTestEncryptorParameters(CHARSET));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void test() throws GeneralSecurityException, IOException {

		final InputStream enc = encryptStream(new ByteArrayInputStream(TEST_VALUE));
		final InputStream dec = decryptStream(enc);
		assertArrayEquals(TEST_VALUE, StreamUtil.streamToBytes(dec));
	}

	/**
	 *
	 */
	@Test
	public void testThreadSafety() {
		final int num = 25;
		final EncryptThread[] threads = new EncryptThread[num];
		for (int i=0; i<num; i++) {
			threads[i] = new EncryptThread();
			threads[i].start();
		}
		for (int i=0; i<num; i++) {
			try {
				threads[i].join();
			}
			catch (final InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private class EncryptThread extends Thread {

		/**
		 * {@inheritDoc}
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<50; i++) {
					final InputStream enc = encryptStream(new ByteArrayInputStream(TEST_VALUE));
					assertArrayEquals(TEST_VALUE, StreamUtil.streamToBytes(decryptStream(enc)));
				}
			}
			catch (final Exception e) {
				e.printStackTrace();
			}
		}

	}

}
