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
package org.antfarmer.ejce.parameter;

import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * AlgorithmParameters object used for RC6 encryption.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class Rc6Parameters extends Abstract128BitBlockCipherParameters<Rc6Parameters> {

	/**
	 * Algorithm for RC6 encryption.
	 */
	public static final String ALGORITHM_RC6 = "RC6";

	/**
	 * Initializes the Rc6Parameters. The default transformation is 'RC6/CBC/PKCS5Padding' with a
	 * block size of 16 bytes and key size of 128 bits.
	 */
	public Rc6Parameters() {
		super();
	}

	/**
	 * Initializes the Rc6Parameters with a {@link TextEncoder} which is used to decode the key when
	 * set as a string. The default transformation is 'RC6/CBC/PKCS5Padding' with a block size of 8
	 * bytes and key size of 128 bits.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	public Rc6Parameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getDefaultAlgorithm() {
		return ALGORITHM_RC6;
	}

}
