/*
 * Copyright 2018 Ameer Antar.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.antfarmer.ejce.util;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * Utility providing methods to compute simple message digests (hashes) using various algorithms.
 * @author Ameer Antar
 */
public class MessageDigestUtil {

	/**
	 * The MD2 message digest algorithm as defined in RFC 1319. Produces a 128 bit digest.
	 */
	public static final String ALGORITHM_MD2 = "MD2";

	/**
	 * The MD5 message digest algorithm as defined in RFC 1321. Produces a 128 bit digest.
	 */
	public static final String ALGORITHM_MD5 = "MD5";

	/**
	 * The SHA1 algorithm defined in FIPS PUB 180-4. Produces a 160 bit digest.
	 */
	public static final String ALGORITHM_SHA1 = "SHA1";

	/**
	 * The SHA-224 algorithm defined in FIPS PUB 180-4. Produces a 224 bit digest.
	 */
	public static final String ALGORITHM_SHA2_224 = "SHA-224";

	/**
	 * The SHA-256 algorithm defined in FIPS PUB 180-4. Produces a 256 bit digest.
	 */
	public static final String ALGORITHM_SHA2_256 = "SHA-256";

	/**
	 * The SHA-384 algorithm defined in FIPS PUB 180-4. Produces a 384 bit digest.
	 */
	public static final String ALGORITHM_SHA2_384 = "SHA-384";

	/**
	 * The SHA-512 algorithm defined in FIPS PUB 180-4. Produces a 512 bit digest.
	 */
	public static final String ALGORITHM_SHA2_512 = "SHA-512";

	/**
	 * The SHA-512/224 algorithm defined in FIPS PUB 180-4.
	 */
	public static final String ALGORITHM_SHA2_512_224 = "SHA-512/224";

	/**
	 * The SHA-512/256 algorithm defined in FIPS PUB 180-4.
	 */
	public static final String ALGORITHM_SHA2_512_256 = "SHA-512/256";

	/**
	 * The SHA3-224 Permutation-based hash and extendable-output function as defined in FIPS PUB 202. SHA3-224 produces a 224 bit digest.
	 */
	public static final String ALGORITHM_SHA3_224 = "SHA3-224";

	/**
	 * The SHA3-256 Permutation-based hash and extendable-output function as defined in FIPS PUB 202. SHA3-256 produces a 256 bit digest.
	 */
	public static final String ALGORITHM_SHA3_256 = "SHA3-256";

	/**
	 * The SHA3-384 Permutation-based hash and extendable-output function as defined in FIPS PUB 202. SHA3-384 produces a 384 bit digest.
	 */
	public static final String ALGORITHM_SHA3_384 = "SHA3-384";

	/**
	 * The SHA3-512 Permutation-based hash and extendable-output function as defined in FIPS PUB 202. SHA3-512 produces a 512 bit digest.
	 */
	public static final String ALGORITHM_SHA3_512 = "SHA3-512";


	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	private MessageDigestUtil() {
		// static only
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using a Base64Encoder.
	 * @param text the text
	 * @param algorithm the MessageDigest algorithm
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static String hashString(final String text, final String algorithm)
			throws NoSuchAlgorithmException {
		return hashString(text, algorithm, Base64Encoder.getInstance());
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using a Base64Encoder.
	 * @param text the text
	 * @param charset the {@link Charset} used for the given text
	 * @param algorithm the MessageDigest algorithm
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static String hashString(final String text, final Charset charset, final String algorithm)
			throws NoSuchAlgorithmException {
		return hashString(text, charset, algorithm, Base64Encoder.getInstance());
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using the given TextEncoder.
	 * @param text the text
	 * @param algorithm the MessageDigest algorithm
	 * @param encoder the TextEncoder
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static String hashString(final String text, final String algorithm, final TextEncoder encoder)
			throws NoSuchAlgorithmException {
		final byte[] textBytes = text.getBytes(DEFAULT_CHARSET);
		try {
			return encoder.encode(hashBytes(textBytes, algorithm));
		}
		finally {
			ByteUtil.clear(textBytes);
		}
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using the given TextEncoder.
	 * @param text the text
	 * @param charset the {@link Charset} used for the given text
	 * @param algorithm the MessageDigest algorithm
	 * @param encoder the TextEncoder
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static String hashString(final String text, final Charset charset, final String algorithm, final TextEncoder encoder)
			throws NoSuchAlgorithmException {
		final byte[] textBytes = text.getBytes(charset);
		try {
			return encoder.encode(hashBytes(textBytes, algorithm));
		}
		finally {
			ByteUtil.clear(textBytes);
		}
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using a Base64Encoder.
	 * @param text the text
	 * @param algorithm the MessageDigest algorithm
	 * @param provider the JCE-compliant provider (may be null)
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static String hashString(final String text, final String algorithm, final Provider provider, final String providerName)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return hashString(text, algorithm, provider, providerName, Base64Encoder.getInstance());
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using a Base64Encoder.
	 * @param text the text
	 * @param charset the {@link Charset} used for the given text
	 * @param algorithm the MessageDigest algorithm
	 * @param provider the JCE-compliant provider (may be null)
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static String hashString(final String text, final Charset charset, final String algorithm, final Provider provider, final String providerName)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return hashString(text, charset, algorithm, provider, providerName, Base64Encoder.getInstance());
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using the given TextEncoder.
	 * @param text the text
	 * @param algorithm the MessageDigest algorithm
	 * @param provider the JCE-compliant provider (may be null)
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @param encoder the TextEncoder
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static String hashString(final String text, final String algorithm, final Provider provider, final String providerName, final TextEncoder encoder)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] textBytes = text.getBytes(DEFAULT_CHARSET);
		try {
			return encoder.encode(hashBytes(textBytes, algorithm, provider, providerName));
		}
		finally {
			ByteUtil.clear(textBytes);
		}
	}

	/**
	 * Hashes the given text using the given MessageDigest algorithm and encodes the result using the given TextEncoder.
	 * @param text the text
	 * @param charset the {@link Charset} used for the given text
	 * @param algorithm the MessageDigest algorithm
	 * @param provider the JCE-compliant provider (may be null)
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @param encoder the TextEncoder
	 * @return a hash of the given text
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static String hashString(final String text, final Charset charset, final String algorithm, final Provider provider, final String providerName, final TextEncoder encoder)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] textBytes = text.getBytes(charset);
		try {
			return encoder.encode(hashBytes(textBytes, algorithm, provider, providerName));
		}
		finally {
			ByteUtil.clear(textBytes);
		}
	}

	/**
	 * Hashes the given bytes using the given MessageDigest algorithm.
	 * @param bytes the bytes
	 * @param algorithm the MessageDigest algorithm
	 * @return a hash of the given bytes
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 */
	public static byte[] hashBytes(final byte[] bytes, final String algorithm) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance(algorithm);
		return md.digest(bytes);
	}

	/**
	 * Hashes the given bytes using the given MessageDigest algorithm.
	 * @param bytes the bytes
	 * @param algorithm the MessageDigest algorithm
	 * @param provider the JCE-compliant provider (may be null)
	 * @param providerName the name of the JCE-compliant provider (may be null)
	 * @return a hash of the given bytes
	 * @throws NoSuchAlgorithmException NoSuchAlgorithmException
	 * @throws NoSuchProviderException NoSuchProviderException
	 */
	public static byte[] hashBytes(final byte[] bytes, final String algorithm, final Provider provider, final String providerName)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		final MessageDigest md;
		if (provider != null) {
			md = MessageDigest.getInstance(algorithm, provider);
		}
		else if (TextUtil.hasLength(providerName)) {
			md = MessageDigest.getInstance(algorithm, providerName);
		}
		else {
			md = MessageDigest.getInstance(algorithm);
		}
		return md.digest(bytes);
	}

}
