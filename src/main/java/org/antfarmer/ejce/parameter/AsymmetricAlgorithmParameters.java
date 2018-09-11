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

import java.security.Key;

/**
 * Interface for initializing asymmetric encryption algorithms.
 * @author Ameer Antar
 * @param <T> the concrete type of this object
 */
public interface AsymmetricAlgorithmParameters<T extends AsymmetricAlgorithmParameters<T>>
		extends AlgorithmParameters<T> {

	/**
	 * Sets the encryption key.
	 *
	 * @param encryptionKey The encryptionKey to set.
	 * @return this concrete class
	 */
	T setEncryptionKey(Key encryptionKey);

	/**
	 * Sets the <code>KeyLoader</code>, which is used to load the encryption key. The value may either be the
	 * full class name of a <code>KeyLoader</code> implementation or an actual <code>KeyLoader</code>
	 * instance.
	 * @param encryptionKeyLoader The encryptionKeyLoader to set.
	 * @return this concrete class
	 */
	T setEncryptionKeyLoader(Object encryptionKeyLoader);

	/**
	 * Sets the decryption key.
	 *
	 * @param decryptionKey The decryptionKey to set.
	 * @return this concrete class
	 */
	T setDecryptionKey(Key decryptionKey);

	/**
	 * Sets the <code>KeyLoader</code>, which is used to load the decryption key. The value may either be the
	 * full class name of a <code>KeyLoader</code> implementation or an actual <code>KeyLoader</code>
	 * instance.
	 * @param decryptionKeyLoader The decryptionKeyLoader to set.
	 * @return this concrete class
	 */
	T setDecryptionKeyLoader(Object decryptionKeyLoader);

}
