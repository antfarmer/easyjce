package org.antfarmer.ejce.parameter;

import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * AlgorithmParameters object used for ElGamal encryption.
 * @author Ameer Antar
 */
public class ElGamalParameters extends AbstractAsymmetricAlgorithmParameters<ElGamalParameters> {

	/**
	 * Algorithm for ElGamal encryption.
	 */
	public static final String ALGORITHM_ELGAMAL = "ElGamal";

	/**
	 * Initializes the ElGamalParameters. The default transformation is 'ElGamal' with a key size of 128 bits.
	 */
	public ElGamalParameters() {
		super();
	}

	/**
	 * Initializes the ElGamalParameters with a {@link TextEncoder} which is used to decode the key when set as a
	 * string. The default transformation is 'ElGamal' with a key size of 128 bits.
	 * @param textEncoder the {@link TextEncoder}
	 */
	public ElGamalParameters(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getDefaultAlgorithm() {
		return ALGORITHM_ELGAMAL;
	}

}
