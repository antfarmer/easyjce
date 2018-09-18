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
package org.antfarmer.ejce.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.util.Random;
import java.util.concurrent.Callable;

import org.antfarmer.common.Loggable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Ameer Antar
 */
public abstract class AbstractTest extends Loggable {

	protected static final Charset UTF8 = Charset.forName("UTF-8");

	protected static final Random RANDOM = new Random();

	protected static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

	/**
	 * @return a random ASCII letter
	 */
	protected static byte nextAscii() {
		return (byte) (33 + RANDOM.nextInt(94));
	}

	/**
	 * Fills the given array with random ASCII bytes.
	 * @param bytes the byte array
	 * @return the byte array
	 */
	protected static byte[] nextAsciiBytes(final byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = nextAscii();
		}
		return bytes;
	}

	/**
	 * Converts the given text to a byte array using the UTF-8 charset.
	 * @param text the text
	 * @return the byte representation of the given text
	 */
	protected static byte[] toBytes(final String text) {
		return text.getBytes(UTF8);
	}

	/**
	 * Asserts that the given operation triggers the expected exception.
	 * @param exc the expected {@link Throwable}
	 * @param operation the {@link Callable} operation
	 */
	protected static void assertException(final Class<? extends Throwable> exc, final Operation operation) {
		assertException(exc, null, operation);
	}

	/**
	 * Asserts that the given operation triggers the expected exception and contains the message phrase.
	 * @param exc the expected {@link Throwable}
	 * @param messagePhrase the phrase that should be contained in the exception message (if any)
	 * @param operation the {@link Callable} operation
	 */
	protected static void assertException(final Class<? extends Throwable> exc, final String messagePhrase, final Operation operation) {
		Throwable ex = null;
		try {
			operation.run();
		}
		catch (final Throwable e) {
			ex = e;
		}
		assertNotNull(ex);
		assertSame(exc, ex.getClass());
		if (messagePhrase != null) {
			assertTrue(ex.getMessage(), ex.getMessage().contains(messagePhrase));
		}
	}

	public static interface Operation {
		void run() throws Throwable;
	}

}
