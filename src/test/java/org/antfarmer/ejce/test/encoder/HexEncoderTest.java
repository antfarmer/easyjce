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
package org.antfarmer.ejce.test.encoder;

import org.antfarmer.ejce.encoder.HexEncoder;
import org.antfarmer.ejce.encoder.TextEncoder;
import org.junit.Test;

/**
 * @author Ameer Antar
 * @version 1.1
 */
public class HexEncoderTest extends AbstractEncoderTest {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected TextEncoder getEncoder() {
		return HexEncoder.getInstance();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getEncodedCharsetPattern() {
		return "[A-F0-9]+";
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidLength() {
		final byte[] bytes = {1};
		encoder.decode(new String(bytes));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidChar1() {
		final byte[] bytes = {-1, 0};
		encoder.decode(new String(bytes));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidChar2() {
		final byte[] bytes = {127, 0};
		encoder.decode(new String(bytes));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidChar3() {
		final byte[] bytes = {120, 0};
		encoder.decode(new String(bytes));
	}
}
