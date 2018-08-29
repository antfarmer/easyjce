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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;

import org.antfarmer.ejce.util.StreamUtil;
import org.hibernate.engine.spi.SessionImplementor;

/**
 * Hibernate UserType class which encrypts and decrypts arbitrarily large text values transparently.
 * This ensures data is stored in it's encrypted form in persistent storage, while not affecting it's
 * real value in the application.
 * @author Ameer Antar
 */
public class EncryptedTextType extends EncryptedClobType {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Class<?> returnedClass() {
		return String.class;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected InputStream lobToStream(final Object value) throws SQLException {
		return value instanceof String ? new ByteArrayInputStream(((String) value).getBytes(getCharset())) : super.lobToStream(value);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Object createLob(final InputStream is, final long length, final SessionImplementor session) throws IOException {
 		return new String(StreamUtil.streamToBytes(is), getCharset());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Object createLob(final byte[] bytes, final SessionImplementor session) throws IOException {
 		return new String(bytes, getCharset());
	}

}
