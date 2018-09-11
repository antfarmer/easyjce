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
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Properties;

import javax.crypto.Cipher;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.EncryptorStore;
import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.parameter.AbstractBlockCipherParameters;
import org.antfarmer.ejce.parameter.AlgorithmParameters;
import org.antfarmer.ejce.parameter.AsymmetricAlgorithmParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.parameter.SymmetricAlgorithmParameters;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;
import org.antfarmer.ejce.password.ConfigurablePasswordEncoder;
import org.antfarmer.ejce.password.PasswordEncoderStore;

/**
 * Configuration utility for instantiating an <code>Encryptor</code> using a <code>Properties</code> object for
 * configuration.
 * @author Ameer Antar
 * @version 1.0
 */
public final class ConfigurerUtil {

	/**
	 * Property key for the prefix to be used to lookup configuration settings within the system properties.
	 */
	public static final String KEY_PROPERTY_PREFIX = "propertyPrefix";

	/**
	 * Property key for the {@link EncryptorStore} key which maps to a code-configured {@link Encryptor}.
	 */
	public static final String KEY_ENCRYPTOR_STORE_KEY = "storeKey";

	/**
	 * Property key for the full class name of the {@link TextEncoder} to be used with the {@link Encryptor}.
	 */
	public static final String KEY_ENCODER_CLASS = "encoder";

	/**
	 * Property key for the full class name of the {@link TextEncoder} to be used with the {@link Encryptor}.
	 */
	public static final String KEY_CHARSET = "charset";

	/**
	 * Property key for the full class name of the algorithm parameter class to be used to configure the
	 * {@link Encryptor}.
	 */
	public static final String KEY_PARAM_CLASS = "paramClass";

	/**
	 * Property key for the full class name of the {@link TextEncoder} to be used with the algorithm parameter object.
	 */
	public static final String KEY_PARAM_ENCODER_CLASS = "paramEncoder";

	/**
	 * Property key for the encryption key to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_CIPHER_KEY = "key";

	/**
	 * Property key for the encryption KeyLoader to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_KEY_LOADER = "keyLoader";

	/**
	 * Property key for the encryption key to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_ENCRYPTION_KEY = "encryptionkey";

	/**
	 * Property key for the encryption key to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_DECRYPTION_KEY = "decryptionkey";

	/**
	 * Property key for the encryption algorithm to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_ALGORITHM = "algorithm";

	/**
	 * Property key for the JCE provider name to be used with the {@link Encryptor}.
	 */
	public static final String KEY_PROVIDER_NAME = "providerName";

	/**
	 * Property key for the JCE provider class to be used with the {@link Encryptor}.
	 */
	public static final String KEY_PROVIDER_CLASS = "providerClass";

	/**
	 * Property key for the MAC key to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_MAC_KEY = "macKey";

	/**
	 * Property key for the MAC KeyLoader to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_MAC_KEY_LOADER = "macKeyLoader";

	/**
	 * Property key for the MAC algorithm to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_MAC_ALGORITHM = "macAlgorithm";

	/**
	 * Property key for the <code>SaltGenerator</code> to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_SALT_GENERATOR = "saltGenerator";

	/**
	 * Property key for the <code>SaltMatcher</code> to be used to configure the {@link Encryptor}.
	 */
	public static final String KEY_SALT_MATCHER = "saltMatcher";

	/**
	 * Property key for the block mode to be used with the encryption algorithm.
	 */
	public static final String KEY_BLOCK_MODE = "blockMode";

	/**
	 * Property key for the block size to be used with the encryption algorithm.
	 */
	public static final String KEY_BLOCK_SIZE = "blockSize";

	/**
	 * Property key for the Authentication Tag length in bits to be used with the encryption algorithm in GCM block mode.
	 */
	public static final String KEY_GCM_TAG_LEN = "gcmTagLen";

	/**
	 * Property key for the padding to be used with the encryption algorithm.
	 */
	public static final String KEY_PADDING = "padding";

	/**
	 * Property key for the salt size (in bytes) to be used with a PBE algorithm.
	 */
	public static final String KEY_SALT_SIZE = "saltSize";

	/**
	 * Property key for the number of PBE iterations to be used with a PBE algorithm.
	 */
	public static final String KEY_ITERATION_COUNT = "iterations";

	/**
	 * Property key for enabling compression of LOB data. Used only by types extending <code>AbstractLobType</code>.
	 */
	public static final String KEY_COMPRESS_LOB = "compress";

	/**
	 * Property key for enabling streaming of LOB data. Used only by types extending <code>AbstractLobType</code>.
	 */
	public static final String KEY_STREAM_LOBS = "streamLobs";

	/**
	 * Property key that controls in-memory buffer size used in LOB-type streaming in pre-JDBC4 environments. Used only
	 * by types extending <code>AbstractLobType</code>.
	 */
	public static final String KEY_STREAM_BUFF_SIZE = "streamBuffSize";

	/**
	 * Property key that controls the maxmimum in-memory buffer size used in LOB-type streaming in pre-JDBC4
	 * environments. Used only by types extending <code>AbstractLobType</code>.
	 */
	public static final String KEY_MAX_IN_MEM_BUFF_SIZE = "maxInMemBuffSize";

	/**
	 * Property key for the full class name of the {@link ConfigurablePasswordEncoder} to
	 * be used with the {@link org.antfarmer.ejce.password.EncodedPasswordType}.
	 */
	public static final String KEY_PSWD_ENCODER_ADAPTER_CLASS = "encoderAdapter";

	/**
	 * Property key for the key to be used to export the {@link ConfigurablePasswordEncoder} into the
	 * {@link PasswordEncoderStore}. This allows the application to easily reference the password encoder.
	 */
	public static final String KEY_PSWD_ENCODER_STORE_EXPORT_KEY = "storeExportKey";

	private static final String METHOD_ENCODER_GET_INSTANCE = "getInstance";

	private static final String FIELD_TEXT_ENCODER = "textEncoder";

	private static final String FIELD_ALGORITHM = "algorithm";

	private ConfigurerUtil() {
		// static methods only
	}

	/**
	 * Loads and configures an encryptor based on settings within the given properties.
	 *
	 * @param properties the properties with encryptor settings
	 * @return an encryptor based on settings within the given properties
	 * @throws EncryptorConfigurationException an error was found with the given configuration
	 */
	public static Encryptor configureEncryptor(final Properties properties)
			throws EncryptorConfigurationException {
		return configureEncryptor(properties, null);
	}

	/**
	 * Loads and configures an encryptor based on settings within the given properties. The prefix is prepended on each
	 * of the property keys.
	 *
	 * @param properties the properties with encryptor settings
	 * @param prefix prefix to be used with the property keys
	 * @return an encryptor based on settings within the given properties
	 * @throws EncryptorConfigurationException an error was found with the given configuration
	 */
	public static Encryptor configureEncryptor(final Properties properties, final String prefix)
			throws EncryptorConfigurationException {
		Encryptor encryptor;

		// get encryptor settings from system properties
		String property = properties.getProperty(getPropertyName(prefix, KEY_PROPERTY_PREFIX));
		if (TextUtil.hasLength(property)) {
			if (properties == System.getProperties()) {
				throw new EncryptorConfigurationException("Cannot set " + KEY_PROPERTY_PREFIX
						+ " within system properties.");
			}
			return configureEncryptor(System.getProperties(), property);
		}

		// get encryptor from store if encryptor name is set
		property = properties.getProperty(getPropertyName(prefix, KEY_ENCRYPTOR_STORE_KEY));
		if (TextUtil.hasLength(property)) {
			encryptor = EncryptorStore.get(property);
			if (encryptor == null) {
				throw new EncryptorConfigurationException("Could not find encryptor in store with name: "
						+ property);
			}
			return encryptor;
		}

		// instantiate text encoder for encryptor
		TextEncoder encoder = null;
		property = properties.getProperty(getPropertyName(prefix, KEY_ENCODER_CLASS));
		if (!TextUtil.hasLength(property)) {
			property = Base64Encoder.class.getName();
		}
		try {
			encoder = (TextEncoder) Class.forName(property).getMethod(METHOD_ENCODER_GET_INSTANCE).invoke(null);
		}
		catch (final Exception e) {
			throw new EncryptorConfigurationException("Error instantiating: " + property, e);
		}

		// load charset for encryptor
		Charset charset = null;
		property = properties.getProperty(getPropertyName(prefix, KEY_CHARSET));
		if (TextUtil.hasLength(property)) {
			try {
				charset = Charset.forName(property.trim());
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error loading charset: " + property, e);
			}
		}

		// prepare encryptor using mapping file parameters
		encryptor = new Encryptor(encoder, charset);
		return encryptor.setAlgorithmParameters(loadAlgorithmParameters(properties, prefix));
	}

	/**
	 * Loads an <tt>AlgorithmParameters</tt> instance for the given encryption configuration parameters.
	 * @param parameters the encryption configuration parameters
	 * @param prefix the property key prefix (may be null)
	 * @return an <tt>AlgorithmParameters</tt> instance for the given encryption configuration parameters
	 * @throws EncryptorConfigurationException an error was found with the given configuration
	 */
	public static AlgorithmParameters<?> loadAlgorithmParameters(final Properties parameters, final String prefix)
			throws EncryptorConfigurationException {
		AlgorithmParameters<?> algorithmParameters = null;
		String property;

		// instantiate algorithmParameters
		property = parameters.getProperty(getPropertyName(prefix, KEY_PARAM_CLASS));
		if (!TextUtil.hasLength(property)) {
			throw new EncryptorConfigurationException("Missing '" + KEY_PARAM_CLASS
					+ "' property in Hibernate mapping.");
		}

		final Class<?> algParamClass;
		try {
			algParamClass = Class.forName(property);
		}
		catch (final Exception e) {
			throw new EncryptorConfigurationException("Error instantiating: " + property, e);
		}
		if (AsymmetricAlgorithmParameters.class.isAssignableFrom(algParamClass)) {
			throw new EncryptorConfigurationException("Asymmetric ciphers are not supported using property configuration.");
		}
		try {
			algorithmParameters = (AlgorithmParameters<?>) algParamClass.newInstance();
		}
		catch (final Exception e) {
			throw new EncryptorConfigurationException("Error instantiating: " + property, e);
		}

		// instantiate text encoder if necessary
		property = parameters.getProperty(getPropertyName(prefix, KEY_PARAM_ENCODER_CLASS));
		if (TextUtil.hasLength(property)) {
			try {
				final TextEncoder encoder = (TextEncoder) Class.forName(property).getMethod(METHOD_ENCODER_GET_INSTANCE).invoke(null);
				ReflectionUtil.setFieldValue(algorithmParameters, encoder, FIELD_TEXT_ENCODER);
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error instantiating: " + property, e);
			}
		}

		// set algorithm
		property = parameters.getProperty(getPropertyName(prefix, KEY_ALGORITHM));
		if (TextUtil.hasLength(property)) {
			try {
				ReflectionUtil.setFieldValue(algorithmParameters, property, FIELD_ALGORITHM);
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error setting '" + FIELD_ALGORITHM + "' on "
						+ algorithmParameters.getClass().getSimpleName(), e);
			}
		}

		// set key
		property = parameters.getProperty(getPropertyName(prefix, KEY_CIPHER_KEY));
		final String loaderProperty = parameters.getProperty(getPropertyName(prefix, KEY_KEY_LOADER));
		if (!(TextUtil.hasLength(property) || TextUtil.hasLength(loaderProperty))) {
			throw new EncryptorConfigurationException("Missing '" + KEY_CIPHER_KEY
				+ "' or '" + KEY_KEY_LOADER + "' property in Hibernate mapping.");
		}
		if (TextUtil.hasLength(property)) {
			((SymmetricAlgorithmParameters<?>) algorithmParameters).setKey(property);
		}
		else {
			((SymmetricAlgorithmParameters<?>) algorithmParameters).setKeyLoader(loaderProperty);
		}

		// set providerName
		property = parameters.getProperty(getPropertyName(prefix, KEY_PROVIDER_NAME));
		if (TextUtil.hasLength(property)) {
			algorithmParameters.setProviderName(property);
		}

		// set provider
		property = parameters.getProperty(getPropertyName(prefix, KEY_PROVIDER_CLASS));
		if (TextUtil.hasLength(property)) {
			try {
				algorithmParameters.setProvider((Provider) Class.forName(property).newInstance());
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error instantiating: " + property, e);
			}
		}

		// set mac key
		property = parameters.getProperty(getPropertyName(prefix, KEY_MAC_KEY));
		if (TextUtil.hasLength(property)) {
			algorithmParameters.setMacKey(property);
		}
		else {
			property = parameters.getProperty(getPropertyName(prefix, KEY_MAC_KEY_LOADER));
			if (TextUtil.hasLength(property)) {
				algorithmParameters.setMacKeyLoader(property);
			}
		}

		// set mac algorithm
		property = parameters.getProperty(getPropertyName(prefix, KEY_MAC_ALGORITHM));
		if (TextUtil.hasLength(property)) {
			algorithmParameters.setMacAlgorithm(property);
		}

		// set salt generator
		property = parameters.getProperty(getPropertyName(prefix, KEY_SALT_GENERATOR));
		if (TextUtil.hasLength(property)) {
			try {
				algorithmParameters.setSaltGenerator((SaltGenerator) Class.forName(property).newInstance());
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error instantiating: " + property, e);
			}
		}

		// set salt matcher
		property = parameters.getProperty(getPropertyName(prefix, KEY_SALT_MATCHER));
		if (TextUtil.hasLength(property)) {
			try {
				algorithmParameters.setSaltMatcher((SaltMatcher) Class.forName(property).newInstance());
			}
			catch (final Exception e) {
				throw new EncryptorConfigurationException("Error instantiating: " + property, e);
			}
		}

		// if not a block cipher, return
		if (!(algorithmParameters instanceof AbstractBlockCipherParameters)) {
			return algorithmParameters;
		}
		final AbstractBlockCipherParameters<?> blockCipherParameters = (AbstractBlockCipherParameters<?>) algorithmParameters;

		// set block mode
		property = parameters.getProperty(getPropertyName(prefix, KEY_BLOCK_MODE));
		if (TextUtil.hasLength(property)) {
			blockCipherParameters.setBlockMode(property);
		}

		Integer intVal;
		// set block size
		property = parameters.getProperty(getPropertyName(prefix, KEY_BLOCK_SIZE));
		intVal = parseInt(property);
		if (intVal != null) {
			blockCipherParameters.setBlockSize(intVal);
		}

		// set GCM authentication tag length
		property = parameters.getProperty(getPropertyName(prefix, KEY_GCM_TAG_LEN));
		intVal = parseInt(property);
		if (intVal != null) {
			blockCipherParameters.setGcmTagLen(intVal);
		}

		// set block padding
		property = parameters.getProperty(getPropertyName(prefix, KEY_PADDING));
		if (TextUtil.hasLength(property)) {
			blockCipherParameters.setPadding(property);
		}

		// if not a PBE cipher, return
		if (!PbeParameters.class.isAssignableFrom(algorithmParameters.getClass())) {
			return algorithmParameters;
		}
		final PbeParameters pbeParameters = PbeParameters.class.cast(algorithmParameters);

		// set salt size
		property = parameters.getProperty(getPropertyName(prefix, KEY_SALT_SIZE));
		intVal = parseInt(property);
		if (intVal != null) {
			pbeParameters.setSaltSize(intVal);
		}

		// set iteration count
		property = parameters.getProperty(getPropertyName(prefix, KEY_ITERATION_COUNT));
		intVal = parseInt(property);
		if (intVal != null) {
			pbeParameters.setIterationCount(intVal);
		}

		return algorithmParameters;
	}


	/**
	 * Loads and configures a {@link ConfigurablePasswordEncoder} based on settings within the given properties.
	 *
	 * @param properties the properties with password encoder settings
	 * @return a {@link ConfigurablePasswordEncoder} based on settings within the given properties
	 * @throws EncryptorConfigurationException an error was found with the given configuration
	 */
	public static ConfigurablePasswordEncoder configurePswdEncoder(final Properties properties)
			throws EncryptorConfigurationException {
		return configurePswdEncoder(properties, null);
	}

	/**
	 * Loads and configures a {@link ConfigurablePasswordEncoder} based on settings within the given properties.
	 * The prefix is prepended on each of the property keys.
	 *
	 * @param properties the properties with password encoder settings
	 * @param prefix prefix to be used with the property keys
	 * @return a {@link ConfigurablePasswordEncoder} based on settings within the given properties
	 * @throws EncryptorConfigurationException an error was found with the given configuration
	 */
	public static ConfigurablePasswordEncoder configurePswdEncoder(final Properties properties, final String prefix)
			throws EncryptorConfigurationException {
		ConfigurablePasswordEncoder pswdEncoder;

		// get password encoder settings from system properties
		String property = properties.getProperty(getPropertyName(prefix, KEY_PROPERTY_PREFIX));
		if (TextUtil.hasLength(property)) {
			if (properties == System.getProperties()) {
				throw new EncryptorConfigurationException("Cannot set " + KEY_PROPERTY_PREFIX + " within system properties.");
			}
			return configurePswdEncoder(System.getProperties(), property);
		}

		// get password encoder from store if password encoder name is set
		property = properties.getProperty(getPropertyName(prefix, KEY_ENCRYPTOR_STORE_KEY));
		if (TextUtil.hasLength(property)) {
			pswdEncoder = PasswordEncoderStore.get(property);
			if (pswdEncoder == null) {
				throw new EncryptorConfigurationException("Could not find password encoder in store with name: " + property);
			}
			return pswdEncoder;
		}

		// load adapter class
		property = properties.getProperty(getPropertyName(prefix, KEY_PSWD_ENCODER_ADAPTER_CLASS));
		if (!TextUtil.hasLength(property)) {
			throw new EncryptorConfigurationException("Missing '" + KEY_PSWD_ENCODER_ADAPTER_CLASS + "' property in Hibernate mapping");
		}
		try {
			final Class<?> adapterClass = Class.forName(property);
			if (!ConfigurablePasswordEncoder.class.isAssignableFrom(adapterClass)) {
				throw new EncryptorConfigurationException(property + " must implement " + ConfigurablePasswordEncoder.class.getName());
			}
			pswdEncoder = (ConfigurablePasswordEncoder) adapterClass.newInstance();
		}
		catch (final Exception e) {
			throw new EncryptorConfigurationException("Error instantiating: " + property, e);
		}

		// configure
		pswdEncoder.configure(properties, prefix);

		// export password encoder to store if export key is set
		property = properties.getProperty(getPropertyName(prefix, KEY_PSWD_ENCODER_STORE_EXPORT_KEY));
		if (TextUtil.hasLength(property)) {
			PasswordEncoderStore.add(property, pswdEncoder);
		}

		return pswdEncoder;
	}

	/**
	 * Returns a <code>Cipher</code> instance for the given <code>AlgorithmParameters</code>.
	 * @param parameters the <code>AlgorithmParameters</code>
	 * @return a <code>Cipher</code> instance for the given <code>AlgorithmParameters</code>
	 * @throws GeneralSecurityException
	 */
	public static Cipher getCipherInstance(final AlgorithmParameters<?> parameters)
			throws GeneralSecurityException {
		final String transformation = parameters.getTransformation();
		if (parameters.getProvider() != null) {
			return Cipher.getInstance(transformation, parameters.getProvider());
		}
		if (parameters.getProviderName() != null) {
			return Cipher.getInstance(transformation, parameters.getProviderName());
		}
		return Cipher.getInstance(transformation);
	}

	/**
	 * Parses the given string as an integer.
	 * @param value the input string
	 * @return the integer value of the given string, or null if the string does not represent an integer
	 */
	public static Integer parseInt(final String value) {
		if (value == null) {
			return null;
		}
		try {
			return Integer.valueOf(value.trim());
		}
		catch (final NumberFormatException e) {
			return null;
		}
	}

	private static String getPropertyName(final String prefix, final String baseName) {
		return prefix == null ? baseName : prefix + "." + baseName;
	}

}
