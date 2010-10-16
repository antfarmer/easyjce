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
 * Abstract AlgorithmParameters class for 128-bit block cipher encryption algorithms.
 *
 * @author Ameer Antar
 * @version 1.0
 * @param <T> the concrete type of this object.
 */
public abstract class Abstract128BitBlockCipherParameters<T extends Abstract128BitBlockCipherParameters<T>>
		extends AbstractBlockCipherParameters<T> {

	/**
	 * Default block cipher size in bytes for 128-bit block size ciphers.
	 */
	public static final int DEFAULT_BLOCK_SIZE = 16;

	/**
	 * Initializes the Abstract128BitBlockCipherParameters.
	 */
	protected Abstract128BitBlockCipherParameters() {
		super();
	}

	/**
	 * Initializes the Abstract128BitBlockCipherParameters with a {@link TextEncoder} which is used
	 * to decode the key when set as a string.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	protected Abstract128BitBlockCipherParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getDefaultBlockSize() {
		return DEFAULT_BLOCK_SIZE;
	}

}
