package org.antfarmer.ejce.parameter;

import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * AlgorithmParameters object used for RSA encryption.
 * @author Ameer Antar
 */
public class RsaParameters extends AbstractAsymmetricAlgorithmParameters<RsaParameters> {

	/**
	 * Algorithm for RSA encryption.
	 */
	public static final String ALGORITHM_RSA = "RSA";

	/**
	 * 512-bit key size.
	 */
	public static final int KEY_SIZE_512 = 512;

	/**
	 * 768-bit key size.
	 */
	public static final int KEY_SIZE_768 = 768;

	/**
	 * 1024-bit key size.
	 */
	public static final int KEY_SIZE_1024 = 1024;

	/**
	 * 2048-bit key size.
	 */
	public static final int KEY_SIZE_2048 = 2048;

	/**
	 * 3072-bit key size.
	 */
	public static final int KEY_SIZE_3072 = 3072;

	/**
	 * 4096-bit key size.
	 */
	public static final int KEY_SIZE_4096 = 4096;

	/**
	 * No padding.
	 */
	public static final String PADDING_NONE = "NoPadding";

	/**
	 * The padding scheme described in: RSA Laboratories, "PKCS #1: RSA Encryption Standard," version 1.5, November
	 * 1993.
	 */
	public static final String PADDING_PKCS1 = "PKCS1Padding";

	/**
	 * Optimal Asymmetric Encryption Padding scheme defined in PKCS #1, with SHA1 message digest and MGF1 mask
	 * generation function.
	 */
	public static final String PADDING_OAEP_SHA1_MGF1 = "OAEPWithSHA1AndMGF1Padding";

	/**
	 * Optimal Asymmetric Encryption Padding scheme defined in PKCS #1, with MD5 message digest and MGF1 mask generation
	 * function.
	 */
	public static final String PADDING_OAEP_MD5_MGF1 = "OAEPWithMD5AndMGF1Padding";

	/**
	 * Initializes the RsaParameters. The default transformation is 'RSA' with a key size of 512 bits.
	 */
	public RsaParameters() {
		super();
	}

	/**
	 * Initializes the RsaParameters with a {@link TextEncoder} which is used to decode the key when set as a string.
	 * The default transformation is 'RSA' with a key size of 512 bits.
	 * @param textEncoder the {@link TextEncoder}
	 */
	public RsaParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getDefaultAlgorithm() {
		return ALGORITHM_RSA;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected int getDefaultKeySize() {
		return KEY_SIZE_512;
	}

}
