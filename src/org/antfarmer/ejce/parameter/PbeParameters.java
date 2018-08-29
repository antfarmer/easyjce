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

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.PBEParameterSpec;

import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * AlgorithmParameters object used for PBE (Password-Based Encryption).
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class PbeParameters extends AbstractBlockCipherParameters<PbeParameters> {

	/**
	 * Algorithm for PBEWithMD5AndDES encryption.
	 */
	public static final String ALGORITHM_PBE_MD5_DES = "PBEWithMD5AndDES";

	/**
	 * Algorithm for PBEWithHmacSHA1AndDESede encryption.
	 */
	public static final String ALGORITHM_PBE_SHA1_DES_EDE = "PBEWithHmacSHA1AndDESede";

	/**
	 * Default size of salt array in bytes. The default value is 8.
	 */
	public static final int DEFAULT_SALT_SIZE = 8;

	/**
	 * Default number of PBE iterations. The default value is 500.
	 */
	public static final int DEFAULT_ITERATION_COUNT = 500;

	/**
	 * Default size of randomly generated passwords in bytes. The default value is 20.
	 */
	public static final int DEFAULT_PASSWORD_SIZE = 16;

	private int saltSize = DEFAULT_SALT_SIZE;

	private int iterationCount = DEFAULT_ITERATION_COUNT;

	/**
	 * Initializes the PbeParameters. The default transformation is 'PBEWithMD5AndDES'.
	 */
	public PbeParameters() {
		super();
	}

	/**
	 * Initializes the PbeParameters with a {@link TextEncoder} which is used to decode the key when
	 * set as a string. The default transformation is 'PBEWithMD5AndDES'.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	public PbeParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PbeParameters setAlgorithm(final String algorithm) {
		return super.setAlgorithm(algorithm);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getDefaultAlgorithm() {
		return ALGORITHM_PBE_MD5_DES;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getTransformation() {
		return getAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getParameterSpecSize() {
		return saltSize;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AlgorithmParameterSpec getParameterSpec(final byte[] messageData) throws GeneralSecurityException {
		if (getParameterSpecSize() > 0) {
			return new PBEParameterSpec(parseAndVerifySalt(messageData), iterationCount);
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AlgorithmParameterSpec createParameterSpec(final byte[] parameterData) {
		if (parameterData == null) {
			return new PBEParameterSpec(new byte[0], iterationCount);
		}
		return new PBEParameterSpec(parameterData, iterationCount);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected byte[] generateKeyData(final String algorithm) throws GeneralSecurityException {
		final byte[] data = new byte[DEFAULT_PASSWORD_SIZE];
		random.nextBytes(data);
		return data;
	}

	/**
	 * Returns the saltSize value.
	 * @return the saltSize.
	 */
	public int getSaltSize() {
		return saltSize;
	}

	/**
	 * Sets the saltSize value.
	 * @param saltSize The saltSize to set.
	 * @return this class
	 */
	public PbeParameters setSaltSize(final int saltSize) {
		this.saltSize = saltSize;
		return this;
	}

	/**
	 * Returns the iterationCount value.
	 * @return the iterationCount.
	 */
	public int getIterationCount() {
		return iterationCount;
	}

	/**
	 * Sets the iterationCount value.
	 * @param iterationCount The iterationCount to set.
	 * @return this class
	 */
	public PbeParameters setIterationCount(final int iterationCount) {
		this.iterationCount = iterationCount;
		return this;
	}

}
