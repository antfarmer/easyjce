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
package org.antfarmer.ejce.hibernate;

import java.security.GeneralSecurityException;

/**
 * Hibernate UserType class which encrypts and decrypts string values transparently. This ensures
 * data is stored in it's encrypted form in persistent storage, while not affecting it's real value
 * in the application.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedStringType extends AbstractHibernateType {

	/**
	 * {@inheritDoc}
	 */
	public Class<?> returnedClass() {
		return String.class;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Object decrypt(final String value) throws GeneralSecurityException {
		return getEncryptor().decrypt(value);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String encrypt(final Object value) throws GeneralSecurityException {
		return getEncryptor().encrypt((String) value);
	}

}
