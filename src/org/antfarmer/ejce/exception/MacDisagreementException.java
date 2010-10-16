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
package org.antfarmer.ejce.exception;

import java.security.GeneralSecurityException;

/**
 * Exception which indicates the MAC (Message authentication code) received in an encrypted message
 * did not match the MAC for the decrypted message. This indicates the message was tampered with or
 * a communication error occurred between encryption and decryption.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class MacDisagreementException extends GeneralSecurityException {

	private static final long serialVersionUID = 3116123153914994213L;

	/**
	 * Initializes the MacDisagreementException.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public MacDisagreementException(final String message, final Throwable cause) {
		super(message, cause);
	}

	/**
	 * Initializes the MacDisagreementException.
	 *
	 * @param message the message
	 */
	public MacDisagreementException(final String message) {
		super(message);
	}

	/**
	 * Initializes the MacDisagreementException.
	 *
	 * @param cause the cause
	 */
	public MacDisagreementException(final Throwable cause) {
		super(cause);
	}

}
