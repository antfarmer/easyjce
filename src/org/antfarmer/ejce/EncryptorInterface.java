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
package org.antfarmer.ejce;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;

import org.antfarmer.ejce.parameter.AlgorithmParameters;


/**
 * Interface for encrypting/decrypting byte arrays.
 *
 * @author Ameer Antar
 * @version 1.0
 * @param <T> the concrete type of this Encryptor object.
 */
public interface EncryptorInterface<T extends EncryptorInterface<T>> {

	/**
	 * Initializes the encryptor. AlgorithmParameters must be set before calling this method.
	 *
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	void initialize() throws GeneralSecurityException;

	/**
	 * Encrypts the byte array.
	 *
	 * @param bytes the byte array to be encrypted
	 * @return the encrypted byte array
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	byte[] encrypt(byte[] bytes) throws GeneralSecurityException;

	/**
	 * Encrypts the byte array using the given <code>Key</code>.
	 *
	 * @param bytes the byte array to be encrypted
	 * @param encKey the encryption key
	 * @return the encrypted byte array
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	byte[] encrypt(byte[] bytes, Key encKey) throws GeneralSecurityException;

	/**
	 * Decrypts the byte array.
	 *
	 * @param bytes the byte array to be decrypted
	 * @return the decrypted byte array
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	byte[] decrypt(byte[] bytes) throws GeneralSecurityException;

	/**
	 * Decrypts the byte array using the given <code>Key</code>.
	 *
	 * @param bytes the byte array to be decrypted
	 * @param decKey the decryption key
	 * @return the decrypted byte array
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	byte[] decrypt(byte[] bytes, Key decKey) throws GeneralSecurityException;

	/**
	 * Sets the algorithm parameters used for initialization.
	 *
	 * @param parameters the algorithm parameters
	 * @return this encryptor
	 */
	T setAlgorithmParameters(AlgorithmParameters<?> parameters);

	/**
	 * Gets the algorithm parameters used for initialization.
	 *
	 * @return the algorithm parameters used for initialization
	 */
	AlgorithmParameters<?> getAlgorithmParameters();

	/**
	 * Indicates whether or not the encryptor has been initialized.
	 *
	 * @return true if the encryptor has been initialized, false otherwise
	 */
	boolean isInitialized();

	/**
	 * Returns the charset used by the encryptor.
	 * @return the charset used by the encryptor
	 */
	Charset getCharset();
}
