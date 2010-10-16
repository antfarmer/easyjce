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
package org.antfarmer.ejce;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import org.antfarmer.ejce.exception.MacDisagreementException;
import org.antfarmer.ejce.parameter.AlgorithmParameters;


/**
 * Abstract class for encrypting/decrypting byte arrays.
 *
 * @author Ameer Antar
 * @version 1.2
 * @param <T> the concrete type of this encryptor object.
 */
public abstract class AbstractEncryptor<T extends AbstractEncryptor<T>> implements EncryptorInterface<T> {

	private boolean initialized;

	private boolean macEnabled;

	private AlgorithmParameters<?> parameters;

	private Key encryptionKey;

	private Key decryptionKey;

	private Cipher encryptor;

	private Cipher decryptor;

	private Key macKey;

	private Mac encMac;

	private Mac decMac;

	private final ReentrantLock initLock = new ReentrantLock();
	private final ReentrantLock encLock = new ReentrantLock();
	private final ReentrantLock encMacLock = new ReentrantLock();
	private final ReentrantLock decLock = new ReentrantLock();
	private final ReentrantLock decMacLock = new ReentrantLock();

	/**
	 * {@inheritDoc}
	 */
	public void initialize() throws GeneralSecurityException {
		initLock.lock();
		try {
			if (initialized) {
				return;
			}
			if (parameters == null) {
				throw new GeneralSecurityException(
						"AlgorithmParameters must be set before initializing.");
			}
			// setup key and ciphers
			encryptionKey = parameters.getEncryptionKey();
			decryptionKey = parameters.getDecryptionKey();
			final String transformation = parameters.getTransformation();
			encryptor = getCipherInstance(transformation);
			decryptor = getCipherInstance(transformation);

			// setup MAC if required
			if (parameters.getMacAlgorithm() != null && parameters.getMacKey() != null) {
				encMac = getMacInstance(parameters.getMacAlgorithm());
				decMac = getMacInstance(parameters.getMacAlgorithm());
				macKey = parameters.getMacKey();
				macEnabled = true;
			}

			initialized = true;
		}
		finally {
			initLock.unlock();
		}
	}

	private Cipher getCipherInstance(final String transformation)
			throws GeneralSecurityException {
		if (parameters.getProvider() != null) {
			return Cipher.getInstance(transformation, parameters.getProvider());
		}
		if (parameters.getProviderName() != null) {
			return Cipher.getInstance(transformation, parameters.getProviderName());
		}
		return Cipher.getInstance(transformation);
	}

	private Mac getMacInstance(final String transformation)
			throws GeneralSecurityException {
		if (parameters.getProvider() != null) {
			return Mac.getInstance(transformation, parameters.getProvider());
		}
		if (parameters.getProviderName() != null) {
			return Mac.getInstance(transformation, parameters.getProviderName());
		}
		return Mac.getInstance(transformation);
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] encrypt(final byte[] bytes) throws GeneralSecurityException {
		return encrypt(bytes, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] encrypt(final byte[] bytes, final Key encKey) throws GeneralSecurityException {
		if (bytes == null) {
			return null;
		}
		int cLen;
		byte[] enciphered;
		final int paramSize = parameters.getParameterSpecSize();

		encLock.lock();
		try {
			final byte[] paramData = parameters.generateParameterSpecData();
			final AlgorithmParameterSpec paramSpec = parameters.createParameterSpec(paramData);
			encryptor.init(Cipher.ENCRYPT_MODE, encKey == null ? encryptionKey : encKey, paramSpec);
			if (macEnabled) {
				encMacLock.lock();
				try {
					encMac.init(macKey);
					enciphered = new byte[encryptor.getOutputSize(bytes.length + encMac.getMacLength())
							+ paramSize];
					cLen = encryptor.update(bytes, 0, bytes.length, enciphered, 0);
					cLen += encryptor.doFinal(encMac.doFinal(bytes), 0, encMac.getMacLength(),
							enciphered, cLen);
				}
				finally {
					encMacLock.unlock();
				}
			}
			else {
				enciphered = new byte[encryptor.getOutputSize(bytes.length) + paramSize];
				cLen = encryptor.doFinal(bytes, 0, bytes.length, enciphered, 0);
			}
			if (paramSize > 0) {
				System.arraycopy(paramData, 0, enciphered, cLen, paramSize);
			}
		}
		finally {
			encLock.unlock();
		}

		return enciphered;
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] decrypt(final byte[] bytes) throws GeneralSecurityException {
		return decrypt(bytes, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] decrypt(final byte[] bytes, final Key decKey) throws GeneralSecurityException {
		if (bytes == null) {
			return null;
		}
		int inputLen = bytes.length;
		AlgorithmParameterSpec algorithmSpec = null;
		final int paramSize = parameters.getParameterSpecSize();
		if (paramSize > 0) {
			inputLen -= paramSize;
			algorithmSpec = parameters.getParameterSpec(bytes);
		}
		byte[] buff;
		decLock.lock();
		try {
			decryptor.init(Cipher.DECRYPT_MODE, decKey == null ? decryptionKey : decKey, algorithmSpec);
			buff = decryptor.doFinal(bytes, 0, inputLen);
		}
		finally {
			decLock.unlock();
		}
		if (!macEnabled) {
			return buff;
		}

		byte[] deciphered;
		decMacLock.lock();
		try {
			decMac.init(macKey);
			deciphered = new byte[buff.length - decMac.getMacLength()];
			final byte[] rcvdMac = new byte[decMac.getMacLength()];
			System.arraycopy(buff, 0, deciphered, 0, deciphered.length);
			System.arraycopy(buff, deciphered.length, rcvdMac, 0, rcvdMac.length);

			if (!MessageDigest.isEqual(rcvdMac, decMac.doFinal(deciphered))) {
				throw new MacDisagreementException(
						"MAC disagreement. This message may have been tampered with.");
			}
		}
		finally {
			decMacLock.unlock();
		}

		return deciphered;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isInitialized() {
		initLock.lock();
		try {
			return initialized;
		}
		finally {
			initLock.unlock();
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@SuppressWarnings("unchecked")
	public T setAlgorithmParameters(final AlgorithmParameters<?> parameters) {
		this.parameters = parameters;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	public AlgorithmParameters<?> getAlgorithmParameters() {
		return parameters;
	}

}
