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

/**
 * Interface for initializing symmetric encryption algorithms.
 * @author Ameer Antar
 * @param <T> the concrete type of this object
 */
public interface SymmetricAlgorithmParameters<T extends SymmetricAlgorithmParameters<T>>
		extends AlgorithmParameters<T> {

	/**
	 * Returns the key.
	 *
	 * @return the key.
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Key getKey() throws GeneralSecurityException;

	/**
	 * Sets the raw byte array of the key.
	 *
	 * @param key The encryptionKey to set.
	 * @return this concrete class
	 */
	T setKey(byte[] key);

	/**
	 * Sets the key. If a text encoder has been set, the text will first be decoded, otherwise
	 * the raw bytes of the string will be used as the key.
	 *
	 * @param key The key to set.
	 * @return this concrete class
	 */
	T setKey(String key);

	/**
	 * Sets the key.
	 *
	 * @param key The key to set.
	 * @return this concrete class
	 */
	T setKey(Key key);

	/**
	 * Sets the <code>KeyLoader</code>, which is used to load the key. The value may either be the
	 * full class name of a <code>KeyLoader</code> implementation or an actual <code>KeyLoader</code>
	 * instance.
	 * @param keyLoader The keyLoader to set.
	 * @return this concrete class
	 */
	T setKeyLoader(Object keyLoader);

}
