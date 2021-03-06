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

import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.parameter.key_loader.KeyLoader;
import org.antfarmer.ejce.util.ByteUtil;
import org.antfarmer.ejce.util.CryptoUtil;

/**
 * Abstract SymmetricAlgorithmParameters class.
 * @author Ameer Antar
 * @param <T> the concrete type of this object
 */
public abstract class AbstractSymmetricAlgorithmParameters<T extends AbstractSymmetricAlgorithmParameters<T>>
		extends AbstractAlgorithmParameters<T> implements SymmetricAlgorithmParameters<T> {

	/**
	 * Initializes the AbstractSymmetricAlgorithmParameters.
	 */
	protected AbstractSymmetricAlgorithmParameters() {
		super();
	}

	/**
	 * Initializes the AbstractSymmetricAlgorithmParameters with a {@link TextEncoder} which is used to
	 * decode the key when set as a string.
	 *
	 * @param textEncoder the {@link TextEncoder}
	 */
	protected AbstractSymmetricAlgorithmParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getKey() throws GeneralSecurityException {
		return getEncryptionKey();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setKey(final byte[] key) {
		return super.setEncryptionKey(key);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setKey(final String key) {
		return super.setEncryptionKey(key);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setKey(final Key key) {
		return super.setEncryptionKey(key);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T setKeyLoader(final Object keyLoader) {
		return super.setEncryptionKeyLoader(keyLoader);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getDecryptionKey() throws GeneralSecurityException {
		return super.getEncryptionKey();
	}

	/**
	 * Returns a randomly generated byte array used to create a key.
	 * @param algorithm the algorithm for the key
	 * @return a randomly generated byte array used to create a key
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	protected byte[] generateKeyData(final String algorithm) throws GeneralSecurityException {
		return CryptoUtil.generateSecretKey(getKeySize(), algorithm, getProviderName(), getProvider()).getEncoded();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Key loadKey(final byte[] rawKey, final KeyLoader keyLoader, final String algorithm)
			throws GeneralSecurityException {
		try {
			if (keyLoader != null) {
				return keyLoader.loadKey(algorithm);
			}

			byte[] keyBytes;
			if (rawKey == null) {
				keyBytes = generateKeyData(algorithm);
			}
			else {
				keyBytes = rawKey;
			}
			return CryptoUtil.getSecretKeyFromRawKey(keyBytes, algorithm);
		}
		finally {
			ByteUtil.clear(rawKey);
		}
	}

}
