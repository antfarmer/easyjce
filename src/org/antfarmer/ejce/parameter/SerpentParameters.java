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
 * AlgorithmParameters object used for Serpent encryption.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class SerpentParameters extends Abstract128BitBlockCipherParameters<SerpentParameters> {

	/**
	 * Algorithm for Serpent encryption.
	 */
	public static final String ALGORITHM_SERPENT = "Serpent";

	/**
	 * Initializes the SerpentParameters. The default transformation is 'Serpent/CBC/PKCS5Padding' with a
	 * block size of 16 bytes and key size of 128 bits.
	 */
	public SerpentParameters() {
		super();
	}

	/**
	 * Initializes the SerpentParameters with a {@link TextEncoder} which is used to decode the key
	 * when set as a string. The default transformation is 'Serpent/CBC/PKCS5Padding' with a block
	 * size of 16 bytes and key size of 128 bits.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	public SerpentParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getDefaultAlgorithm() {
		return ALGORITHM_SERPENT;
	}

}
