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

import javax.crypto.spec.GCMParameterSpec;
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
	 * Default IV (parameter specification) size in bytes for GCM block mode. The default value is 12.
	 */
	public static final int DEFAULT_PARAM_SPEC_SIZE_GCM = 12;

	/**
	 * Cipher Block Chaining Block Mode, as defined in FIPS PUB 81.
	 */
	public static final String BLOCK_MODE_CBC = "CBC";

	/**
	 * Counter/CBC Mode, as defined in NIST Special Publication SP 800-38C.
	 */
	public static final String BLOCK_MODE_CCM = "CCM";

	/**
	 * Cipher Feedback Block Mode, as defined in FIPS PUB 81.
	 */
	public static final String BLOCK_MODE_CFB = "CFB";

	/**
	 * A simplification of OFB, Counter mode updates the input block as a counter.
	 */
	public static final String BLOCK_MODE_CTR = "CTR";

	/**
	 * Cipher Text Stealing, as described in Bruce Schneier's book Applied Cryptography-Second Edition, John Wiley and Sons, 1996.
	 */
	public static final String BLOCK_MODE_CTS = "CTS";

	/**
	 * Electronic Codebook Block Mode, as defined in: The National Institute of Standards and
	 * Technology (NIST) Federal Information Processing Standard (FIPS) PUB 81, "DES Modes of
	 * Operation," U.S. Department of Commerce, December 1980.
	 */
	public static final String BLOCK_MODE_ECB = "ECB";

	/**
	 * Galois/Counter Mode, as defined in NIST Special Publication SP 800-38D.
	 */
	public static final String BLOCK_MODE_GCM = "GCM";

	/**
	 * Output Feedback Block Mode, as defined in FIPS PUB 81.
	 */
	public static final String BLOCK_MODE_OFB = "OFB";

	/**
	 * Propagating Cipher Block Chaining Block Mode, as defined by Kerberos V4.
	 */
	public static final String BLOCK_MODE_PCBC = "PCBC";


	/**
	 * 96-bit Authentication Tag length for GCM block mode ciphers, as defined in NIST Special Publication SP 800-38D.
	 */
	public static final int GCM_AUTH_TAG_LEN_96 = 96;

	/**
	 * 104-bit Authentication Tag length for GCM block mode ciphers, as defined in NIST Special Publication SP 800-38D.
	 */
	public static final int GCM_AUTH_TAG_LEN_104 = 104;

	/**
	 * 112-bit Authentication Tag length for GCM block mode ciphers, as defined in NIST Special Publication SP 800-38D.
	 */
	public static final int GCM_AUTH_TAG_LEN_112 = 112;

	/**
	 * 120-bit Authentication Tag length for GCM block mode ciphers, as defined in NIST Special Publication SP 800-38D.
	 */
	public static final int GCM_AUTH_TAG_LEN_120 = 120;

	/**
	 * 128-bit Authentication Tag length for GCM block mode ciphers, as defined in NIST Special Publication SP 800-38D.
	 */
	public static final int GCM_AUTH_TAG_LEN_128 = 128;


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

	private int gcmTagLen = GCM_AUTH_TAG_LEN_128;

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
	@Override
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
	@Override
	public int getParameterSpecSize() {
		if (BLOCK_MODE_ECB.equalsIgnoreCase(blockMode)) {
			return 0;
		}
		if (BLOCK_MODE_GCM.equalsIgnoreCase(blockMode)) {
			return DEFAULT_PARAM_SPEC_SIZE_GCM;
		}
		return getDefaultBlockSize();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AlgorithmParameterSpec createParameterSpec(final byte[] parameterData) {
		if (parameterData == null) {
			return null;
		}
		if (BLOCK_MODE_GCM.equalsIgnoreCase(blockMode)) {
			return new GCMParameterSpec(gcmTagLen, parameterData);
		}
		return new IvParameterSpec(parameterData);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AlgorithmParameterSpec getParameterSpec(final byte[] messageData) throws GeneralSecurityException {
		if (messageData.length < getParameterSpecSize()) {
			throw new GeneralSecurityException("Incorrect encrypted data size.");
		}
		final byte[] iv = parseAndVerifySalt(messageData);
		if (BLOCK_MODE_GCM.equalsIgnoreCase(blockMode)) {
			return new GCMParameterSpec(gcmTagLen, iv);
		}
		return new IvParameterSpec(iv);
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
	 * Returns the GCM block mode Authentication Tag length in bits.
	 *
	 * @return the gcmTagLen
	 */
	public int getGcmTagLen() {
		return gcmTagLen;
	}

	/**
	 * Sets the GCM block mode Authentication Tag length in bits.
	 *
	 * @param gcmTagLen the gcmTagLen to set
	 * @return the concrete class
	 */
	@SuppressWarnings("unchecked")
	public T setGcmTagLen(final int gcmTagLen) {
		this.gcmTagLen = gcmTagLen;
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
