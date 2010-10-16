/*
 * Copyright 2006-2009 the original author or authors.
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
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;


/**
 * Interface for initializing encryption algorithms.
 *
 * @author Ameer Antar
 * @version 1.1
 * @param <T> the concrete type of this object
 */
public interface AlgorithmParameters<T extends AlgorithmParameters<T>> {

	/**
	 * Returns the algorithm value.
	 *
	 * @return the algorithm.
	 */
	String getAlgorithm();

	/**
	 * Returns the transformation value.
	 *
	 * @return the transformation.
	 */
	String getTransformation();

	/**
	 * Returns the key used for encryption.
	 *
	 * @return the key used for encryption.
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Key getEncryptionKey() throws GeneralSecurityException;

	/**
	 * Returns the key used for decryption.
	 *
	 * @return the key used for decryption.
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Key getDecryptionKey() throws GeneralSecurityException;

	/**
	 * Generates a byte array which holds algorithm parameters such as an initialization vector or
	 * salt.
	 *
	 * @return an array of bytes which holds algorithm parameters
	 */
	byte[] generateParameterSpecData();

	/**
	 * Generates an algorithm-specific {@link AlgorithmParameterSpec} object used to hold algorithm
	 * parameters such as an initialization vector or salt.
	 *
	 * @param parameterData the data for the {@link AlgorithmParameterSpec}
	 * @return an algorithm-specific {@link AlgorithmParameterSpec} object
	 */
	AlgorithmParameterSpec createParameterSpec(byte[] parameterData);

	/**
	 * Returns an algorithm-specific {@link AlgorithmParameterSpec} object used to hold algorithm
	 * parameters such as an initialization vector or salt from the enciphered message.
	 *
	 * @param messageData the message data byte array which holds the parameter data
	 * @return an algorithm-specific {@link AlgorithmParameterSpec} object
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	AlgorithmParameterSpec getParameterSpec(byte[] messageData) throws GeneralSecurityException;

	/**
	 * Returns the algorithm parameter data size.
	 *
	 * @return the algorithm parameter data size.
	 */
	int getParameterSpecSize();

	/**
	 * Returns the size of the key to be generated in bits.
	 *
	 * @return the keySize.
	 */
	int getKeySize();

	/**
	 * Sets the size of the key in bits to be generated during initialization. This value is only
	 * used if the key has not been set.
	 *
	 * @param keySize The keySize to set.
	 * @return this concrete class
	 */
	T setKeySize(int keySize);

	/**
	 * Returns the size of the MAC key to be generated in bits.
	 *
	 * @return the macKeySize.
	 */
	int getMacKeySize();

	/**
	 * Sets the size of the MAC key in bits to be generated during initialization. This value is only
	 * used if the MAC key has not been set.
	 *
	 * @param macKeySize The macKeySize to set.
	 * @return this concrete class
	 */
	T setMacKeySize(int macKeySize);

	/**
	 * Returns the macKey.
	 *
	 * @return the macKey.
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Key getMacKey() throws GeneralSecurityException;

	/**
	 * Sets the raw byte array of the MAC key.
	 *
	 * @param macKey The macKey to set.
	 * @return this concrete class
	 */
	T setMacKey(byte[] macKey);

	/**
	 * Sets the macKey. If a text encoder has been set, the text will first be decoded, otherwise
	 * the raw bytes of the string will be used as the MAC key.
	 *
	 * @param macKey The macKey to set.
	 * @return this concrete class
	 */
	T setMacKey(String macKey);

	/**
	 * Sets the macKey.
	 *
	 * @param macKey The macKey to set.
	 * @return this concrete class
	 */
	T setMacKey(Key macKey);

	/**
	 * Returns the macAlgorithm value.
	 *
	 * @return the macAlgorithm.
	 */
	String getMacAlgorithm();

	/**
	 * Sets the macAlgorithm value.
	 *
	 * @param macAlgorithm The macAlgorithm to set.
	 * @return this concrete class
	 */
	T setMacAlgorithm(String macAlgorithm);

	/**
	 * Returns the Java Security Provider name.
	 *
	 * @return the providerName.
	 */
	String getProviderName();

	/**
	 * Sets the Java Security Provider name.
	 *
	 * @param providerName The providerName to set.
	 * @return this concrete class
	 */
	T setProviderName(String providerName);

	/**
	 * Returns the Java Security Provider.
	 *
	 * @return the provider.
	 */
	Provider getProvider();

	/**
	 * Sets the Java Security Provider.
	 *
	 * @param provider The provider to set.
	 * @return this concrete class
	 */
	T setProvider(Provider provider);

	/**
	 * Sets the <code>KeyLoader</code>, which is used to load the cipher key for the MAC. The value may
	 * either be the full class name of a <code>KeyLoader</code> implementation or an actual
	 * <code>KeyLoader</code> instance.
	 * @param macKeyLoader The macKeyLoader to set.
	 * @return this concrete class
	 */
	T setMacKeyLoader(Object macKeyLoader);

	/**
	 * Sets the <code>SaltGenerator</code>, which allows for custom salt data generation.
	 * @param saltGenerator the saltGenerator to set
	 * @return this concrete class
	 */
	T setSaltGenerator(SaltGenerator saltGenerator);

	/**
	 * Sets the <code>SaltMatcher</code>, which may be used to verify the salt within the cipher text matches some
	 * expected value.
	 * @param saltMatcher the saltMatcher to set
	 * @return this concrete class
	 */
	T setSaltMatcher(SaltMatcher saltMatcher);
}
