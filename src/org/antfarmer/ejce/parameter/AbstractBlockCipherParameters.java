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

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.antfarmer.ejce.encoder.TextEncoder;


/**
 * Abstract AlgorithmParameters class for block cipher encryption algorithms.
 *
 * @author Ameer Antar
 * @version 1.0
 * @param <T> the concrete type of this object.
 */
public abstract class AbstractBlockCipherParameters<T extends AbstractBlockCipherParameters<T>>
		extends AbstractSymmetricAlgorithmParameters<T> {

	/**
	 * Default block cipher size in bytes. The default value is 8.
	 */
	public static final int DEFAULT_BLOCK_SIZE = 8;

	/**
	 * Cipher Block Chaining Block Mode, as defined in FIPS PUB 81.
	 */
	public static final String BLOCK_MODE_CBC = "CBC";

	/**
	 * Cipher Feedback Block Mode, as defined in FIPS PUB 81.
	 */
	public static final String BLOCK_MODE_CFB = "CFB";

	/**
	 * Electronic Codebook Block Mode, as defined in: The National Institute of Standards and
	 * Technology (NIST) Federal Information Processing Standard (FIPS) PUB 81, "DES Modes of
	 * Operation," U.S. Department of Commerce, December 1980.
	 */
	public static final String BLOCK_MODE_ECB = "ECB";

	/**
	 * Output Feedback Block Mode, as defined in FIPS PUB 81.
	 */
	public static final String BLOCK_MODE_OFB = "OFB";

	/**
	 * Propagating Cipher Block Chaining Block Mode, as defined by Kerberos V4.
	 */
	public static final String BLOCK_MODE_PCBC = "PCBC";

	/**
	 * No padding.
	 */
	public static final String PADDING_NONE = "NoPadding";

	/**
	 * The padding scheme described in: RSA Laboratories, "PKCS #5: Password-Based Encryption
	 * Standard," version 1.5, November 1993.
	 */
	public static final String PADDING_PKCS5 = "PKCS5Padding";

	/**
	 * The padding scheme described in: RSA Laboratories, "PKCS #7: Cryptographic Message Syntax,"
	 * Version 1.5, November 1993.
	 */
	public static final String PADDING_PKCS7 = "PKCS7Padding";

	private String blockMode = BLOCK_MODE_CBC;

	private int blockSize = getDefaultBlockSize();

	private String padding = PADDING_PKCS5;

	/**
	 * Initializes the AbstractBlockCipherParameters.
	 */
	protected AbstractBlockCipherParameters() {
		super();
	}

	/**
	 * Initializes the AbstractBlockCipherParameters with a {@link TextEncoder} which is used to
	 * decode the key when set as a string.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	protected AbstractBlockCipherParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * Returns the defaultBlockSize in bytes.
	 * @return the defaultBlockSize
	 */
	public int getDefaultBlockSize() {
		return DEFAULT_BLOCK_SIZE;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getTransformation() {
		final int blockSize = getBlockSize();
		final StringBuilder buff = new StringBuilder(getAlgorithm());
		buff.append('/').append(blockMode);
		if (blockSize > 0 && blockSize != getDefaultBlockSize()) {
			buff.append(blockSize);
		}
		buff.append('/').append(padding);
		return buff.toString();
	}

	/**
	 * Returns the blockMode value.
	 *
	 * @return the blockMode.
	 */
	public String getBlockMode() {
		return blockMode;
	}

	/**
	 * Sets the blockMode value.
	 *
	 * @param blockMode The blockMode to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	public T setBlockMode(final String blockMode) {
		this.blockMode = blockMode;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	public int getParameterSpecSize() {
		if (BLOCK_MODE_ECB.equalsIgnoreCase(blockMode)) {
			return 0;
		}
		return getDefaultBlockSize();
	}

	/**
	 * {@inheritDoc}
	 */
	public AlgorithmParameterSpec getParameterSpec(final byte[] messageData) throws GeneralSecurityException {
		if (messageData.length < getParameterSpecSize()) {
			throw new GeneralSecurityException("Incorrect encrypted data size.");
		}
		return new IvParameterSpec(parseAndVerifySalt(messageData));
	}

	/**
	 * Returns the blockSize value in bytes.
	 *
	 * @return the blockSize.
	 */
	public int getBlockSize() {
		if (BLOCK_MODE_CFB.equalsIgnoreCase(blockMode)
				|| BLOCK_MODE_OFB.equalsIgnoreCase(blockMode)) {
			return blockSize;
		}
		if (BLOCK_MODE_ECB.equalsIgnoreCase(blockMode)) {
			return 0;
		}
		return getDefaultBlockSize();
	}

	/**
	 * Sets the blockSize value in bytes.
	 *
	 * @param blockSize The blockSize to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	public T setBlockSize(final int blockSize) {
		this.blockSize = blockSize;
		return (T) this;
	}

	/**
	 * Returns the padding value.
	 *
	 * @return the padding.
	 */
	public String getPadding() {
		return padding;
	}

	/**
	 * Sets the padding value.
	 *
	 * @param padding The padding to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	public T setPadding(final String padding) {
		this.padding = padding;
		return (T) this;
	}

}
