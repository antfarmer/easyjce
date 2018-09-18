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
package org.antfarmer.ejce.test.password;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.password.ConfigurablePasswordEncoder;
import org.antfarmer.ejce.test.AbstractTest;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public abstract class AbstractPasswordTest<P extends ConfigurablePasswordEncoder> extends AbstractTest {

	protected static final String PASSWORD = "PaSSw0rd";
	private static final int THREAD_COUNT = 25;
	private static final int THREAD_ITERATIONS = 50;

	public static final boolean SKIP_PASSWORD_TESTS = false;
	public static final boolean SKIP_THREAD_TESTS = false;

	protected final P encoder = createEncoder();

	/**
	 * @return an encoder to be used for default tests
	 */
	protected abstract P createEncoder();

	/**
	 * @return a fast encoder to be used for long tests, such as thread safety testing
	 */
	protected abstract P createFastEncoder();

	/**
	 * @return an encoder to be used for default tests
	 */
	protected abstract P createEncoder(Properties defaults);

	protected void assertException(final Properties props) {
		assertException(props, EncryptorConfigurationException.class, null);
	}

	protected void assertException(final Properties props, final Class<? extends Throwable> exc) {
		assertException(props, exc, null);
	}

	protected void assertException(final Properties props, final String messagePhrase) {
		assertException(props, EncryptorConfigurationException.class, messagePhrase);
	}

	protected void assertException(final Properties props, final Class<? extends Throwable> exc, final String messagePhrase) {
		assertException(exc, messagePhrase, new Operation() {
			@Override
			public void run() throws Throwable {
				createEncoder(props);
			}
		});
	}

	@Test
	public void testEncode() {
		assumeFalse(SKIP_PASSWORD_TESTS);

		long start;
		start = System.currentTimeMillis();
		final String encoded1 = encoder.encode(PASSWORD);
		System.out.println(encoded1 + " - took " + (System.currentTimeMillis() - start) + "ms");
		start = System.currentTimeMillis();
		final String encoded2 = encoder.encode(PASSWORD);
		System.out.println(encoded2 + " - took " + (System.currentTimeMillis() - start) + "ms");

		assertFalse(PASSWORD.equals(encoded1));
		assertFalse(PASSWORD.equals(encoded2));
		assertFalse(encoded1.equals(encoded2));
		assertTrue(encoder.matches(PASSWORD, encoded1));
		assertTrue(encoder.matches(PASSWORD, encoded2));
	}

	@Test
	public void threadSafetyTest() throws Throwable {
		assumeFalse(SKIP_PASSWORD_TESTS);
		assumeFalse(SKIP_THREAD_TESTS);

		final int num = THREAD_COUNT;
		EncodeThread thread;
		final P encoder = createFastEncoder();
		final List<EncodeThread> threads = new ArrayList<EncodeThread>(num);
		for (int i=0; i<num; i++) {
			thread = new EncodeThread(encoder);
			threads.add(thread);
			thread.start();
		}
		for (int i=0; i<num; i++) {
			thread = threads.get(i);
			thread.join();
			if (thread.exception != null) {
				throw thread.exception;
			}
		}
	}

	/**
	 * Thread used to test thread-safety of encoders.
	 * @author Ameer Antar
	 */
	protected class EncodeThread extends Thread {
		private final P encoder;
		private Throwable exception;

		public EncodeThread(final P encoder) {
			this.encoder = encoder;
		}

		@Override
		public void run() {
			try {
				for (int i=0; i<THREAD_ITERATIONS; i++) {
					final String enc = encoder.encode(PASSWORD);
					assertFalse(enc.equals(PASSWORD));
					assertTrue(encoder.matches(PASSWORD, enc));
				}
			}
			catch (final Throwable e) {
				exception = e;
				e.printStackTrace();
			}
		}

	}

	public static class MyRandom extends SecureRandom {
		private static final long serialVersionUID = 1L;
	}
}
