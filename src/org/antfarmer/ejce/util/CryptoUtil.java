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
package org.antfarmer.ejce.util;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.antfarmer.ejce.encoder.TextEncoder;


/**
 * Provides methods to generate random keys or keys based on a password for a given algorithm.
 *
 * @author Ameer Antar
 * @version 1.1
 */
public final class CryptoUtil {

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	private CryptoUtil() {
		// static methods only
	}

	/**
	 * Generates a new secret key for the given algorithm.
	 *
	 * @param algorithm the algorithm that will be used for key generation
	 * @return the generated secret key
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static SecretKey generateSecretKey(final String algorithm)
			throws NoSuchAlgorithmException {
		return generateSecretKey(0, algorithm);
	}

	/**
	 * Generates a new secret key for the given algorithm and key size.
	 *
	 * @param keySize the size of the key in bits
	 * @param algorithm the algorithm that will be used for key generation
	 * @return the generated secret key
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static SecretKey generateSecretKey(final int keySize, final String algorithm)
			throws NoSuchAlgorithmException {
		try {
			return generateSecretKey(keySize, algorithm, null, null);
		}
		catch (final NoSuchProviderException e) {
			// impossible
			return null;
		}
	}

	/**
	 * Generates a new secret key for the given algorithm and provider.
	 *
	 * @param algorithm the algorithm that will be used for key generation
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @param provider the JCE-compliant provider (may be null)
	 * @return the generated secret key
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static SecretKey generateSecretKey(final String algorithm, final String providerName, final Provider provider)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return generateSecretKey(0, algorithm, providerName, provider);
	}

	/**
	 * Generates a new secret key for the given algorithm, key size, and provider.
	 *
	 * @param keySize the size of the key in bits
	 * @param algorithm the algorithm that will be used for key generation
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @param provider the JCE-compliant provider (may be null)
	 * @return the generated secret key
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static SecretKey generateSecretKey(final int keySize, final String algorithm, final String providerName, final Provider provider)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		final KeyGenerator kgen;
		if (provider != null) {
			kgen = KeyGenerator.getInstance(algorithm, provider);
		}
		else if (providerName != null && providerName.length() > 0) {
			kgen = KeyGenerator.getInstance(algorithm, providerName);
		}
		else {
			kgen = KeyGenerator.getInstance(algorithm);
		}
		if (keySize > 0) {
			kgen.init(keySize);
		}
		return kgen.generateKey();
	}

	/**
	 * Generates a new asymmetric key pair for the given algorithm.
	 *
	 * @param algorithm the algorithm that will be used for key generation
	 * @return the generated asymmetric key pair
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static KeyPair generateAsymmetricKeyPair(final String algorithm)
			throws NoSuchAlgorithmException {
		return generateAsymmetricKeyPair(0, algorithm);
	}

	/**
	 * Generates a new asymmetric key pair for the given algorithm and key size.
	 *
	 * @param keySize the size of the key in bits
	 * @param algorithm the algorithm that will be used for key generation
	 * @return the generated asymmetric key pair
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static KeyPair generateAsymmetricKeyPair(final int keySize, final String algorithm)
			throws NoSuchAlgorithmException {
		try {
			return generateAsymmetricKeyPair(keySize, algorithm, null, null);
		}
		catch (final NoSuchProviderException e) {
			// impossible
			return null;
		}
	}

	/**
	 * Generates a new asymmetric key pair for the given algorithm and provider.
	 *
	 * @param algorithm the algorithm that will be used for key generation
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @param provider the JCE-compliant provider (may be null)
	 * @return the generated asymmetric key pair
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static KeyPair generateAsymmetricKeyPair(final String algorithm, final String providerName, final Provider provider)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return generateAsymmetricKeyPair(0, algorithm, providerName, provider);
	}

	/**
	 * Generates a new asymmetric key pair for the given algorithm, key size, and provider.
	 *
	 * @param keySize the size of the key in bits
	 * @param algorithm the algorithm that will be used for key generation
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @param provider the JCE-compliant provider (may be null)
	 * @return the generated asymmetric key pair
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static KeyPair generateAsymmetricKeyPair(final int keySize, final String algorithm, final String providerName, final Provider provider)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		final KeyPairGenerator kgen;
		if (provider != null) {
			kgen = KeyPairGenerator.getInstance(algorithm, provider);
		}
		else if (providerName != null && providerName.length() > 0) {
			kgen = KeyPairGenerator.getInstance(algorithm, providerName);
		}
		else {
			kgen = KeyPairGenerator.getInstance(algorithm);
		}
		if (keySize > 0) {
			kgen.initialize(keySize);
		}
		return kgen.generateKeyPair();
	}

	/**
	 * Creates a secret key from the supplied text.
	 *
	 * @param textKey the text key
	 * @param algorithm the algorithm that the will be used for key generation
	 * @return the key value
	 */
	public static SecretKey getSecretKeyFromTextKey(final String textKey, final String algorithm) {
		return getSecretKeyFromTextKey(textKey, algorithm, null);
	}

	/**
	 * Creates a secret key from the supplied text. The optional text encoder is used to decode the
	 * key before generating the key.
	 *
	 * @param textKey the text key
	 * @param algorithm the algorithm that will be used for key generation
	 * @param textEncoder the text encoder that will be used to decode the text key (if null, the
	 *            raw bytes will be used).
	 * @return the key value
	 */
	public static SecretKey getSecretKeyFromTextKey(final String textKey, final String algorithm,
			final TextEncoder textEncoder) {
		if (textEncoder == null) {
			return getSecretKeyFromRawKey(textKey.getBytes(DEFAULT_CHARSET), algorithm);
		}
		return getSecretKeyFromRawKey(textEncoder.decode(textKey), algorithm);
	}

	/**
	 * Creates a secret key from the supplied raw key byte array.
	 *
	 * @param rawKey the raw key byte array
	 * @param algorithm the algorithm that will be used for key generation
	 * @return the key value
	 */
	public static SecretKey getSecretKeyFromRawKey(final byte[] rawKey, final String algorithm) {
		return new SecretKeySpec(rawKey, algorithm);
	}

	/**
	 * Returns a PublicKey for the given algorithm and KeySpec.
	 * @param algorithm the algorithm
	 * @param keySpec the KeySpec
	 * @return a PublicKey
	 * @throws InvalidKeySpecException InvalidKeySpecException
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static PublicKey createPublicKey(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException, NoSuchAlgorithmException {
		return KeyFactory.getInstance(algorithm).generatePublic(keySpec);
	}

	/**
	 * Returns a PrivateKey for the given algorithm and KeySpec.
	 * @param algorithm the algorithm
	 * @param keySpec the KeySpec
	 * @return a PrivateKey
	 * @throws InvalidKeySpecException InvalidKeySpecException
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static PrivateKey createPrivateKey(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException, NoSuchAlgorithmException {
		return KeyFactory.getInstance(algorithm).generatePrivate(keySpec);
	}

    /**
     * Returns a KeySpec for the given key and KeySpec implementation class.
     * @param <T> the KeySpec implementation type
     * @param key the Key
     * @param keySpec the KeySpec implementation class
     * @return a KeySpec
	 * @throws InvalidKeySpecException InvalidKeySpecException
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     */
    public static <T extends KeySpec> T getKeySpec(final Key key, final Class<T> keySpec) throws InvalidKeySpecException, NoSuchAlgorithmException {
    	return KeyFactory.getInstance(key.getAlgorithm()).getKeySpec(key, keySpec);
    }

}
