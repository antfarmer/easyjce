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

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.parameter.key_loader.KeyLoader;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;
import org.antfarmer.ejce.util.CryptoUtil;


/**
 * Abstract AlgorithmParameters class.
 *
 * @author Ameer Antar
 * @version 1.1
 * @param <T> the concrete type of this object.
 */
public abstract class AbstractAlgorithmParameters<T extends AbstractAlgorithmParameters<T>>
		implements AlgorithmParameters<T> {

	/**
	 * 128-bit key size.
	 */
	public static final int KEY_SIZE_128 = 128;

	/**
	 * 192-bit key size (not available in all jurisdictions).
	 */
	public static final int KEY_SIZE_192 = 192;

	/**
	 * 256-bit key size (not available in all jurisdictions).
	 */
	public static final int KEY_SIZE_256 = 256;

	/**
	 * 128-bit MAC key size (Suggested minimum key size for HmacMD5).
	 */
	public static final int MAC_KEY_SIZE_128 = 128;

	/**
	 * 160-bit MAC key size (Suggested minimum key size for HmacSHA1).
	 */
	public static final int MAC_KEY_SIZE_160 = 160;

	/**
	 * The HMAC-MD5 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for Message
	 * Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_MD5 = "HmacMD5";

	/**
	 * The HMAC-SHA1 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA1 = "HmacSHA1";

	/**
	 * The HMAC-SHA224 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA224 = "HmacSHA224";

	/**
	 * The HMAC-SHA256 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA256 = "HmacSHA256";

	/**
	 * The HMAC-SHA384 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA384 = "HmacSHA384";

	/**
	 * The HMAC-SHA512 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA512 = "HmacSHA512";

	/**
	 * The HMAC-SHA512/224 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA512_224 = "HmacSHA512/224";

	/**
	 * The HMAC-SHA512/256 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA512_256 = "HmacSHA512/256";

	/**
	 * The HMAC-SHA3-224 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA3_224 = "HmacSHA3-224";

	/**
	 * The HMAC-SHA3-256 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA3_256 = "HmacSHA3-256";

	/**
	 * The HMAC-SHA3-384 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA3_384 = "HmacSHA3-384";

	/**
	 * The HMAC-SHA3-512 keyed-hashing algorithm as defined in RFC 2104: "HMAC: Keyed-Hashing for
	 * Message Authentication" (February 1997).
	 */
	public static final String MAC_ALGORITHM_HMAC_SHA3_512 = "HmacSHA3-512";


	static final SecureRandom random = new SecureRandom();

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	private TextEncoder textEncoder;

	private byte[] encryptionRawKey;

	private Key encryptionKey;

	private KeyLoader encryptionKeyLoader;

	private byte[] decryptionRawKey;

	private Key decryptionKey;

	private KeyLoader decryptionKeyLoader;

	private String algorithm = getDefaultAlgorithm();

	private String providerName;

	private Provider provider;

	private int keySize = getDefaultKeySize();

	private byte[] rawMacKey;

	private Key macKey;

	private KeyLoader macKeyLoader;

	private int macKeySize;

	private String macAlgorithm;

	private SaltGenerator saltGenerator;

	private SaltMatcher saltMatcher;

	/**
	 * Initializes the AbstractAlgorithmParameters.
	 */
	protected AbstractAlgorithmParameters() {
		// do nothing
	}

	/**
	 * Initializes the AbstractAlgorithmParameters with a {@link TextEncoder}.
	 * @param textEncoder the {@link TextEncoder}
	 */
	protected AbstractAlgorithmParameters(final TextEncoder textEncoder) {
		this.textEncoder = textEncoder;
	}

	/**
	 * Returns the defaultAlgorithm.
	 * @return the defaultAlgorithm
	 */
	protected abstract String getDefaultAlgorithm();

	/**
	 * Returns the defaultKeySize.
	 * @return the defaultKeySize
	 */
	protected int getDefaultKeySize() {
		return KEY_SIZE_128;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getKeySize() {
		return keySize;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setKeySize(final int keySize) {
		this.keySize = keySize;
		return (T) this;
	}

	/**
	 * Loads a key from the given possible key sources.
	 * @param rawKey the raw key bytes (may be null)
	 * @param keyLoader the keyLoader (may be null)
	 * @param algorithm the algorithm for the key
	 * @return a key from the given possible key sources
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	protected abstract Key loadKey(byte[] rawKey, KeyLoader keyLoader, String algorithm)
		throws GeneralSecurityException;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getEncryptionKey() throws GeneralSecurityException {
		if (encryptionKey != null) {
			return encryptionKey;
		}
		final Key key = loadKey(encryptionRawKey, encryptionKeyLoader, algorithm);
		if (key != null) {
			encryptionKey = key;
		}
		return encryptionKey;
	}

	/**
	 * Returns true if this instance has a loaded decryptionKey.
	 * @return true if this instance has a loaded decryptionKey; false otherwise
	 */
	protected boolean hasDecryptionKey()  {
		return decryptionKey != null;
	}

	/**
	 * Sets the raw byte array of the encryption key.
	 *
	 * @param encryptionKey The encryptionKey to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setEncryptionKey(final byte[] encryptionKey) {
		this.encryptionRawKey = encryptionKey;
		return (T) this;
	}

	/**
	 * Sets the encryption key. If a text encoder has been set, the text will first be decoded, otherwise
	 * the raw bytes of the string will be used as the encryption key.
	 *
	 * @param encryptionKey The encryptionKey to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setEncryptionKey(final String encryptionKey) {
		if (textEncoder == null) {
			this.encryptionRawKey = encryptionKey.getBytes(DEFAULT_CHARSET);
			return (T) this;
		}
		this.encryptionRawKey = textEncoder.decode(encryptionKey);
		return (T) this;
	}

	/**
	 * Sets the encryption key.
	 *
	 * @param encryptionKey The encryptionKey to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setEncryptionKey(final Key encryptionKey) {
		this.encryptionKey = encryptionKey;
		return (T) this;
	}

	/**
	 * Sets the <code>KeyLoader</code>, which is used to load the encryption key. The value may either be the
	 * full class name of a <code>KeyLoader</code> implementation or an actual <code>KeyLoader</code>
	 * instance.
	 * @param encryptionKeyLoader The encryptionKeyLoader to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setEncryptionKeyLoader(final Object encryptionKeyLoader) {
		this.encryptionKeyLoader = loadKeyLoader(encryptionKeyLoader);
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getDecryptionKey() throws GeneralSecurityException {
		if (decryptionKey != null) {
			return decryptionKey;
		}
		final Key key = loadKey(decryptionRawKey, decryptionKeyLoader, algorithm);
		if (key != null) {
			decryptionKey = key;
		}
		return decryptionKey;
	}

	/**
	 * Returns true if this instance has a loaded encryptionKey.
	 * @return true if this instance has a loaded encryptionKey; false otherwise
	 */
	protected boolean hasEncryptionKey()  {
		return encryptionKey != null;
	}

	/**
	 * Sets the raw byte array of the decryption key.
	 *
	 * @param decryptionKey The decryptionKey to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setDecryptionKey(final byte[] decryptionKey) {
		this.decryptionRawKey = decryptionKey;
		return (T) this;
	}

	/**
	 * Sets the decryption key. If a text encoder has been set, the text will first be decoded, otherwise
	 * the raw bytes of the string will be used as the decryption key.
	 *
	 * @param decryptionKey The decryptionKey to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setDecryptionKey(final String decryptionKey) {
		if (textEncoder == null) {
			this.decryptionRawKey = decryptionKey.getBytes(DEFAULT_CHARSET);
			return (T) this;
		}
		this.decryptionRawKey = textEncoder.decode(decryptionKey);
		return (T) this;
	}

	/**
	 * Sets the decryption key.
	 *
	 * @param decryptionKey The decryptionKey to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setDecryptionKey(final Key decryptionKey) {
		this.decryptionKey = decryptionKey;
		return (T) this;
	}

	/**
	 * Sets the <code>KeyLoader</code>, which is used to load the decryption key. The value may either be the
	 * full class name of a <code>KeyLoader</code> implementation or an actual <code>KeyLoader</code>
	 * instance.
	 * @param decryptionKeyLoader The decryptionKeyLoader to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setDecryptionKeyLoader(final Object decryptionKeyLoader) {
		this.decryptionKeyLoader = loadKeyLoader(decryptionKeyLoader);
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the algorithm value.
	 *
	 * @param algorithm The algorithm to set.
	 * @return this concrete class
	 */
	@SuppressWarnings("unchecked")
	protected T setAlgorithm(final String algorithm) {
		this.algorithm = algorithm;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] generateParameterSpecData() {
		final int paramSize = getParameterSpecSize();
		if (paramSize > 0) {
			final byte[] parameterData = new byte[paramSize];
			if (saltGenerator != null) {
				saltGenerator.generateSalt(parameterData);
			}
			else {
				random.nextBytes(parameterData);
			}
			return parameterData;
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AlgorithmParameterSpec createParameterSpec(final byte[] parameterData) {
		if (parameterData == null) {
			return null;
		}
		return new IvParameterSpec(parameterData);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getMacKeySize() {
		return macKeySize;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setMacKeySize(final int macKeySize) {
		this.macKeySize = macKeySize;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key getMacKey() throws GeneralSecurityException {
		if (macKey != null) {
			return macKey;
		}
		if (macKeyLoader != null) {
			return macKeyLoader.loadKey(macAlgorithm);
		}
		if (rawMacKey == null) {
			if (macKeySize < 1) {
				return null;
			}
			rawMacKey = CryptoUtil.generateSecretKey(macKeySize, macAlgorithm, getProviderName(), getProvider()).getEncoded();
		}
		macKey = CryptoUtil.getSecretKeyFromRawKey(rawMacKey, macAlgorithm);
		return macKey;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setMacKey(final byte[] macKey) {
		this.rawMacKey = macKey;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setMacKey(final String macKey) {
		if (textEncoder == null) {
			this.rawMacKey = macKey.getBytes(DEFAULT_CHARSET);
			return (T) this;
		}
		this.rawMacKey = textEncoder.decode(macKey);
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setMacKey(final Key macKey) {
		this.macKey = macKey;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getMacAlgorithm() {
		return macAlgorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setMacAlgorithm(final String macAlgorithm) {
		this.macAlgorithm = macAlgorithm;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getProviderName() {
		return providerName;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setProviderName(final String providerName) {
		this.providerName = providerName;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Provider getProvider() {
		return provider;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setProvider(final Provider provider) {
		this.provider = provider;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setMacKeyLoader(final Object macKeyLoader) {
		this.macKeyLoader = loadKeyLoader(macKeyLoader);
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setSaltGenerator(final SaltGenerator saltGenerator) {
		this.saltGenerator = saltGenerator;
		return (T) this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T setSaltMatcher(final SaltMatcher saltMatcher) {
		this.saltMatcher = saltMatcher;
		return (T) this;
	}

	/**
	 * Separates and returns the algorithm spec data or salt from the enciphered message. Also executes the
	 * <code>SaltMatcher</code> if one exists.
	 * @param messageData the enciphered message
	 * @return the algorithm spec data or salt from the enciphered message
	 * @throws GeneralSecurityException if an error occurs when verifying a salt match (if one exists)
	 */
	protected byte[] parseAndVerifySalt(final byte[] messageData) throws GeneralSecurityException {
		final int paramSize = getParameterSpecSize();
		final byte[] parameterData = new byte[paramSize];
		System.arraycopy(messageData, messageData.length - paramSize, parameterData, 0, paramSize);
		if (saltMatcher != null) {
			saltMatcher.verifySaltMatch(parameterData);
		}
		return parameterData;
	}

	private KeyLoader loadKeyLoader(final Object keyLoader) {
		if (keyLoader instanceof String) {
			try {
				return (KeyLoader) Class.forName((String) keyLoader).newInstance();
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error instantiating KeyLoader class: "
						+ keyLoader, e);
			}
		}
		else if (keyLoader instanceof KeyLoader) {
			return (KeyLoader) keyLoader;
		}
		else {
			throw new EncryptorConfigurationException("KeyLoader value must either be a KeyLoader"
					+ " instance or a class name of a KeyLoader implementation.");
		}
	}
}
