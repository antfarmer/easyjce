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
package org.antfarmer.ejce.test.hibernate.util;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.EncryptorStore;
import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.parameter.AbstractAlgorithmParameters;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.antfarmer.ejce.util.CryptoUtil;


/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class TypeUtil {

	private static final String ENCRYPTOR_NAME = "encryptor";

	private TypeUtil() {
		// static methods only
	}

	/**
	 * Prepares an encryptor for testing Hibernate user types and adds it to the EncryptorStore.
	 * @return the properties used to configure the Hibernate user type
	 * @throws GeneralSecurityException
	 */
	public static Properties prepareTestEncryptor() throws GeneralSecurityException {
		return prepareTestEncryptor(null);
	}

	/**
	 * Prepares an encryptor for testing Hibernate user types and adds it to the EncryptorStore.
	 * @param charset the optional {@link Charset} to use for the encryptor (may be null)
	 * @return the properties used to configure the Hibernate user type
	 * @throws GeneralSecurityException
	 */
	public static Properties prepareTestEncryptor(final Charset charset) throws GeneralSecurityException {
		final AesParameters parameters = new AesParameters(Base64Encoder.getInstance())
				.setKeySize(AesParameters.KEY_SIZE_128)
				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(AesParameters.MAC_KEY_SIZE_160)
				;
		final Encryptor encryptor = new Encryptor(Base64Encoder.getInstance(), charset)
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		EncryptorStore.add(ENCRYPTOR_NAME, encryptor);

		final Properties props = new Properties();
		props.put(ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY, ENCRYPTOR_NAME);
		return props;
	}

	/**
	 * Prepares a map of encryptor parameters for testing Hibernate user types.
	 * @param charset the optional {@link Charset} to use for the encryptor (may be null)
	 * @return the properties used to configure the Hibernate user type
	 * @throws GeneralSecurityException
	 */
	public static Properties prepareTestEncryptorParameters(final Charset charset) throws GeneralSecurityException {
		return prepareTestEncryptorParameters(charset, null);
	}

	/**
	 * Prepares a map of encryptor parameters for testing Hibernate user types.
	 * @param charset the optional {@link Charset} to use for the encryptor (may be null)
	 * @param defaults default properties
	 * @return the properties used to configure the Hibernate user type
	 * @throws GeneralSecurityException
	 */
	public static Properties prepareTestEncryptorParameters(final Charset charset, final Properties defaults) throws GeneralSecurityException {
		final Properties props = new Properties(defaults);
		final byte[] key = CryptoUtil.generateSecretKey(AbstractAlgorithmParameters.KEY_SIZE_128, AesParameters.ALGORITHM_AES).getEncoded();
		props.put(ConfigurerUtil.KEY_PARAM_CLASS, AesParameters.class.getName());
		props.put(ConfigurerUtil.KEY_CIPHER_KEY, Base64Encoder.getInstance().encode(key));
		props.put(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base64Encoder.class.getName());
		props.put(ConfigurerUtil.KEY_CHARSET, charset.name());
		return props;
	}

}
