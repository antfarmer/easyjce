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

import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * @author Ameer Antar
 * @version 1.1
 */
public class Base64EncoderTest extends AbstractEncoderTest {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected TextEncoder getEncoder() {
		return Base64Encoder.getInstance();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getEncodedCharsetPattern() {
		return "[A-Za-z0-9+/]+";
	}

}
