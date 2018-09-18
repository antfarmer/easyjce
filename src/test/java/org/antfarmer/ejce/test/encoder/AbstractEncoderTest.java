/*
 * Copyright 2018 Ameer Antar
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
package org.antfarmer.ejce.test.encoder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.regex.Pattern;

import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.test.AbstractTest;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
@Ignore
public abstract class AbstractEncoderTest extends AbstractTest {

	private static final String TEST_TEXT = "abcdefghijklmnopqrstuvwxyz";
	private static final int RANDOM_ITERATIONS = 100;
	private static final int RANDOM_MAX_LENGTH = 100;
	private static final int THREAD_COUNT = 25;
	private static final int THREAD_ITERATIONS = 50;

	protected final TextEncoder encoder = getEncoder();

	private final Pattern encodedCharPattern = Pattern.compile(getEncodedCharsetPattern());

	/**
	 * @return the {@link TextEncoder} for this test class
	 */
	protected abstract TextEncoder getEncoder();

	/**
	 * @return the regex pattern matching all possible characters for the given {@link TextEncoder}
	 */
	protected abstract String getEncodedCharsetPattern();

	/**
	 *
	 */
	@Test
	public void test() {
		assertNull(encoder.encode(null));
		assertEquals("", encoder.encode(new byte[0]));
		assertNull(encoder.decode(null));
		assertArrayEquals(new byte[0], encoder.decode(""));
		final String encoded = encoder.encode(TEST_TEXT.getBytes());
		assertTrue(encodedCharPattern.matcher(encoded).matches());
		assertArrayEquals(TEST_TEXT.getBytes(), encoder.decode(encoded));
	}

	/**
	 *
	 */
	@Test
	public void testRandomData() {
		for (int i=0; i<RANDOM_ITERATIONS; i++) {
			final byte[] bytes = new byte[RANDOM.nextInt(RANDOM_MAX_LENGTH) + 1];
			RANDOM.nextBytes(bytes);
			final String encoded = encoder.encode(bytes);
			assertTrue(encodedCharPattern.matcher(encoded).matches());
			assertArrayEquals(bytes, encoder.decode(encoded));
		}
	}

	@Test
	public void threadSafetyTest() throws Throwable {
		final int num = THREAD_COUNT;
		final EncodeThread[] threads = new EncodeThread[num];
		for (int i=0; i<num; i++) {
			threads[i] = new EncodeThread();
			threads[i].start();
		}
		for (int i=0; i<num; i++) {
			threads[i].join();
			if (threads[i].exception != null) {
				throw threads[i].exception;
			}
		}
	}

	/**
	 * Thread used to test thread-safety of encoders.
	 * @author Ameer Antar
	 */
	protected class EncodeThread extends Thread {
		private Throwable exception;

		/**
		 * {@inheritDoc}
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<THREAD_ITERATIONS; i++) {
					final String enc = encoder.encode(TEST_TEXT.getBytes());
					assertArrayEquals(TEST_TEXT.getBytes(), encoder.decode(enc));
				}
			}
			catch (final Throwable e) {
				exception = e;
				e.printStackTrace();
			}
		}

	}

}
