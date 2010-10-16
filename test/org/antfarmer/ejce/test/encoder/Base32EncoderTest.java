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
package org.antfarmer.ejce.test.encoder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.regex.Pattern;

import org.antfarmer.ejce.encoder.Base32Encoder;
import org.junit.Test;


/**
 * @author Ameer Antar
 * @version 1.1
 */
public class Base32EncoderTest {
	
	private static final String TEST_TEXT = "abcdefghijklmnopqrstuvwxyz";
	
	private static final Pattern ENCODED_CHAR_SET = Pattern.compile("[A-Z2-7]+");

	/**
	 * 
	 */
	@Test
	public void test() {
		String encoded = Base32Encoder.getInstance().encode(TEST_TEXT.getBytes());
		assertTrue(ENCODED_CHAR_SET.matcher(encoded).matches());
		assertArrayEquals(TEST_TEXT.getBytes(), Base32Encoder.getInstance().decode(encoded));
	}	

	/**
	 * 
	 */
	@Test
	public void testRandomData() {
		SecureRandom rand = new SecureRandom();
		for (int i=0; i<100; i++) {
			byte[] bytes = new byte[rand.nextInt(100) + 1];
			rand.nextBytes(bytes);
			String encoded = Base32Encoder.getInstance().encode(bytes);
			assertTrue(ENCODED_CHAR_SET.matcher(encoded).matches());
			assertArrayEquals(bytes, Base32Encoder.getInstance().decode(encoded));
		}
	}
	
	/**
	 * 
	 */
	@Test
	public void threadSafetyTest() {
		int num = 25;
		EncodeThread[] threads = new EncodeThread[num];
		for (int i=0; i<num; i++) {
			threads[i] = new EncodeThread();
			threads[i].start();
		}
		for (int i=0; i<num; i++) {
			try {
				threads[i].join();
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private static class EncodeThread extends Thread {

		/**
		 * {@inheritDoc}
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<50; i++) {
					String enc = Base32Encoder.getInstance().encode(TEST_TEXT.getBytes());
					assertArrayEquals(TEST_TEXT.getBytes(), Base32Encoder.getInstance().decode(enc));
				}
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}

}
