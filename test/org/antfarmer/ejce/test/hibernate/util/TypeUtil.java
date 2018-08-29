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

import java.security.GeneralSecurityException;
import java.util.Properties;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.EncryptorStore;
import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.util.ConfigurerUtil;


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
		final AesParameters parameters = new AesParameters(Base64Encoder.getInstance())
				.setKeySize(AesParameters.KEY_SIZE_128)
				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(AesParameters.MAC_KEY_SIZE_160)
				;
		final Encryptor encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		EncryptorStore.add(ENCRYPTOR_NAME, encryptor);

		final Properties props = new Properties();
		props.put(ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY, ENCRYPTOR_NAME);
		return props;
	}

}
