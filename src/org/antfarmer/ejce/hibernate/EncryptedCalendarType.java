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
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Hibernate UserType class which encrypts and decrypts calendar values transparently. This ensures
 * data is stored in it's encrypted form in persistent storage, while not affecting it's real value
 * in the application.
 *
 * @author Ameer Antar
 * @version 1.1
 */
public class EncryptedCalendarType extends AbstractHibernateType {

	/**
	 * {@inheritDoc}
	 */
	public Class<?> returnedClass() {
		return Calendar.class;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Object decrypt(final String value) throws GeneralSecurityException {
		final String text = getEncryptor().decrypt(value);
		final int pos = text.indexOf(' ');
		final Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone(text.substring(pos + 1)));
		calendar.setTimeInMillis(Long.parseLong(text.substring(0, pos)));
		return calendar;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String encrypt(final Object value) throws GeneralSecurityException {
		final Calendar calendar = (Calendar) value;
		return getEncryptor().encrypt(calendar.getTimeInMillis() + " " + calendar.getTimeZone().getID());
	}

}
