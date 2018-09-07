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
import java.security.Key;
import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;

import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.parameter.key_loader.KeyLoader;
import org.antfarmer.ejce.util.CryptoUtil;
import org.antfarmer.ejce.util.TextUtil;

/**
 * Abstract AsymmetricAlgorithmParameters class.
 * @author Ameer Antar
 * @param <T> the concrete type of this object
 */
public abstract class AbstractAsymmetricAlgorithmParameters<T extends AbstractAsymmetricAlgorithmParameters<T>>
		extends AbstractAlgorithmParameters<T> implements AsymmetricAlgorithmParameters<T> {

	private String blockType = "ECB";
	private String padding;

	/**
	 * Initializes the AbstractAsymmetricAlgorithmParameters.
	 */
	protected AbstractAsymmetricAlgorithmParameters() {
		super();
	}

	/**
	 * Initializes the AbstractAsymmetricAlgorithmParameters with a {@link TextEncoder} which is used to
	 * decode the key when set as a string.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	protected AbstractAsymmetricAlgorithmParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Key loadKey(final byte[] rawKey, final KeyLoader keyLoader, final String algorithm)
			throws GeneralSecurityException {
		if (keyLoader != null) {
			return keyLoader.loadKey(algorithm);
		}

		if (rawKey != null) {
			System.err.println("Use of encoded keys are not compatible with asymmetric ciphers."
				+ " Encoded key will be ignored and a random key set will be generated based on set key size.");
		}
		final KeyPair keyPair = CryptoUtil.generateAsymmetricKeyPair(getKeySize(), algorithm, getProviderName(), getProvider());
		if (!hasEncryptionKey()) {
			super.setEncryptionKey(keyPair.getPublic());
		}
		if (!hasDecryptionKey()) {
			super.setDecryptionKey(keyPair.getPrivate());
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setEncryptionKey(final Key encryptionKey) {
		return super.setEncryptionKey(encryptionKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setEncryptionKeyLoader(final Object encryptionKeyLoader) {
		return super.setEncryptionKeyLoader(encryptionKeyLoader);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setDecryptionKey(final Key decryptionKey) {
		return super.setDecryptionKey(decryptionKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setDecryptionKeyLoader(final Object decryptionKeyLoader) {
		return super.setDecryptionKeyLoader(decryptionKeyLoader);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AlgorithmParameterSpec getParameterSpec(final byte[] messageData) throws GeneralSecurityException {
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getParameterSpecSize() {
		return 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getTransformation() {
		final StringBuilder buff = new StringBuilder(getAlgorithm());
		if (TextUtil.hasLength(padding)) {
			buff.append('/').append(blockType).append('/').append(padding);
		}
		return buff.toString();
	}

	/**
	 * Returns the blockType value.
	 * @return the blockType.
	 */
	public String getBlockType() {
		return blockType;
	}

	/**
	 * Sets the blockType value. Generally, possible values include: "ECB" or "None". Setting this value will have no
	 * effect unless a padding scheme is also set.
	 * @param blockType The blockType to set.
	 * @return this concrete instance
	 */
	@SuppressWarnings("unchecked")
	public T setBlockType(final String blockType) {
		this.blockType = blockType;
		return (T) this;
	}

	/**
	 * Returns the padding value.
	 * @return the padding.
	 */
	public String getPadding() {
		return padding;
	}

	/**
	 * Sets the padding value. Setting a padding scheme will select a block type of "ECB". If this is inappropriate,
	 * the block type value should also be set.
	 * @param padding The padding to set.
	 * @return this concrete instance
	 */
	@SuppressWarnings("unchecked")
	public T setPadding(final String padding) {
		this.padding = padding;
		return (T) this;
	}

}
