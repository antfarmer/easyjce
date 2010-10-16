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
package org.antfarmer.ejce.parameter;

import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * AlgorithmParameters object used for Camellia encryption.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class CamelliaParameters extends Abstract128BitBlockCipherParameters<CamelliaParameters> {

	/**
	 * Algorithm for Camellia encryption.
	 */
	public static final String ALGORITHM_CAMELLIA = "Camellia";

	/**
	 * Initializes the CamelliaParameters. The default transformation is 'Camellia/CBC/PKCS5Padding'
	 * with a block size of 16 bytes and key size of 128 bits.
	 */
	public CamelliaParameters() {
		super();
	}

	/**
	 * Initializes the CamelliaParameters with a {@link TextEncoder} which is used to decode the key
	 * when set as a string. The default transformation is 'Camellia/CBC/PKCS5Padding' with a block
	 * size of 16 bytes and key size of 128 bits.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	public CamelliaParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getDefaultAlgorithm() {
		return ALGORITHM_CAMELLIA;
	}

}
