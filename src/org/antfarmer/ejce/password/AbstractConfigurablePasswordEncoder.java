/*
 * Copyright 2018 Ameer Antar.
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
package org.antfarmer.ejce.password;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.antfarmer.ejce.encoder.Base64PaddedEncoder;
import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;

/**
 * Abstract {@link ConfigurablePasswordEncoder} containing configuration parsing methods.
 * @author Ameer Antar
 */
public abstract class AbstractConfigurablePasswordEncoder implements ConfigurablePasswordEncoder {

	/**
	 * Property key for the SecureRandom class name to use for generating salt.
	 */
	public static final String KEY_RANDOM = "random";

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	private static final TextEncoder DEFAULT_TEXT_ENCODER = Base64PaddedEncoder.getInstance();

	private static final Map<String, SecureRandom> randoms = new HashMap<String, SecureRandom>();

	/**
	 * Returns a static {@link SecureRandom} matching the name configured in the given {@link Properties}.
	 * @param parameters the configuration parameters
	 * @param prefix the prefix for the {@link Properties} keys
	 * @return a static {@link SecureRandom} matching the name configured in the given {@link Properties}
	 */
	protected SecureRandom getRandom(final Properties parameters, final String prefix) {
		String className = parameters.getProperty(getPropertyName(prefix, KEY_RANDOM));
		if (className == null || className.length() < 1) {
			className = SecureRandom.class.getName();
		}
		synchronized (randoms) {
			SecureRandom r = randoms.get(className);
			if (r != null) {
				return r;
			}
			r = parseInstance(className);
			randoms.put(className, r);
			return r;
		}
	}

	/**
	 * Parses the property value as an int from the given parameters.
	 * @param parameters the {@link Properties}
	 * @param prefix the property prefix
	 * @param key the property key
	 * @param defaultValue the default value if no value is configured
	 * @return the configured int value or the default value if not configured
	 */
	protected int parseInt(final Properties parameters, final String prefix, final String key, final int defaultValue) {
		final String value = parameters.getProperty(getPropertyName(prefix, key));
		final Integer intVal = parseInt(value);
		return intVal == null ? defaultValue : intVal.intValue();
	}

	/**
	 * Parses the given string as an integer.
	 * @param value the input string
	 * @return the integer value of the given string, or null if the string is empty
	 */
	protected Integer parseInt(final String value) {
		if (value == null || value.length() < 1) {
			return null;
		}
		try {
			return Integer.valueOf(value.trim());
		}
		catch (final NumberFormatException e) {
			throw new EncryptorConfigurationException("Error parsing integer: " + value, e);
		}
	}

	/**
	 * Parses the string as a class name and returns a new instance of that class.
	 * @param value the name of the class
	 * @return a new instance of the given class name
	 */
	@SuppressWarnings("unchecked")
	protected <T> T parseInstance(final String value) {
		if (value == null || value.length() < 1) {
			return null;
		}
		try {
			final Class<?> clazz = Class.forName(value.trim());
			return (T) clazz.newInstance();
		}
		catch (final Exception e) {
			throw new EncryptorConfigurationException("Error creating instance for: " + value, e);
		}
	}

	/**
	 * Parses the property value as a boolean from the given parameters.
	 * @param parameters the {@link Properties}
	 * @param prefix the property prefix
	 * @param key the property key
	 * @param defaultValue the default value if no value is configured
	 * @return the configured boolean value or the default value if not configured
	 */
	protected boolean parseBoolean(final Properties parameters, final String prefix, final String key, final boolean defaultValue) {
		String value = parameters.getProperty(getPropertyName(prefix, key));
		if (value == null || value.length() < 1) {
			return defaultValue;
		}
		value = value.trim();
		return value.equalsIgnoreCase("true") || value.equalsIgnoreCase("1") || value.equalsIgnoreCase("yes");
	}

	/**
	 * Parses the property value from the given parameters.
	 * @param parameters the {@link Properties}
	 * @param prefix the property prefix
	 * @param key the property key
	 * @param defaultValue the default value if no value is configured
	 * @return the configured String value or the default value if not configured
	 */
	protected String parseString(final Properties parameters, final String prefix, final String key, final String defaultValue) {
		final String value = parameters.getProperty(getPropertyName(prefix, key));
		return value == null || value.length() < 1 ? defaultValue : value.trim();
	}

	/**
	 * Returns the property name for the given prefix and key baseName.
	 * @param prefix the property key prefix
	 * @param baseName the property key base name (may be null)
	 * @return the property name for the given prefix and key baseName
	 */
	protected String getPropertyName(final String prefix, final String baseName) {
		return prefix == null ? baseName : prefix + "." + baseName;
	}

	/**
	 * Converts the given {@link CharSequence} to bytes using the default charset.
	 * @param text the text
	 * @return the bytes representing the given text
	 */
	protected byte[] toBytes(final CharSequence text) {
		return text.toString().getBytes(getCharset());
	}

	/**
	 * Encodes the given data using the default text encoder.
	 * @param bytes the data
	 * @return the encoded representation of the given bytes
	 */
	protected String encodeBytes(final byte[] bytes) {
		return getTextEncoder().encode(bytes);
	}

	/**
	 * Decodes the given text using the default text encoder.
	 * @param encoded the encoded text
	 * @return the decoded data of the given text
	 */
	protected byte[] decodeBytes(final String encoded) {
		return getTextEncoder().decode(encoded);
	}

	/**
	 * @return the default {@link Charset} (UTF-8)
	 */
	protected Charset getCharset() {
		return DEFAULT_CHARSET;
	}

	/**
	 * @return the default {@link TextEncoder} (Base64)
	 */
	protected TextEncoder getTextEncoder() {
		return DEFAULT_TEXT_ENCODER;
	}
}
