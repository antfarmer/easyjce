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
package org.antfarmer.ejce.exception;

/**
 * Exception caused by an Encryptor configuration error.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptorConfigurationException extends RuntimeException {

	private static final long serialVersionUID = -3211051483239512543L;

	/**
	 * Initializes the EncryptorConfigurationException.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public EncryptorConfigurationException(final String message, final Throwable cause) {
		super(message, cause);
	}

	/**
	 * Initializes the EncryptorConfigurationException.
	 *
	 * @param message the message
	 */
	public EncryptorConfigurationException(final String message) {
		super(message);
	}

	/**
	 * Initializes the EncryptorConfigurationException.
	 *
	 * @param cause the cause
	 */
	public EncryptorConfigurationException(final Throwable cause) {
		super(cause);
	}

}
