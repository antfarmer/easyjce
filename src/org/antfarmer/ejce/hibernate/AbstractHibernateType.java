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
package org.antfarmer.ejce.hibernate;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantLock;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.ValueEncryptorInterface;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.hibernate.HibernateException;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.usertype.UserType;
import org.hibernate.util.EqualsHelper;

/**
 * Abstract Hibernate UserType class which encrypts and decrypts values transparently. This ensures
 * data is stored in it's encrypted form in persistent storage, while not affecting it's real value
 * in the application.
 *
 * @author Ameer Antar
 * @version 1.2
 */
public abstract class AbstractHibernateType implements UserType, ParameterizedType {

	private static final int[] sqlTypes = new int[] {Types.VARCHAR};

	private ValueEncryptorInterface<Encryptor> encryptor;

	private final ReentrantLock lock = new ReentrantLock();

	/**
	 * Encrypts the given object using an appropriate method for the object type.
	 *
	 * @param value the object to be encrypted
	 * @return a string representation of the encrypted and encoded object
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	protected abstract String encrypt(Object value) throws GeneralSecurityException;

	/**
	 * Decrypts the given string using an appropriate method for the object type.
	 *
	 * @param value the string to be decrypted
	 * @return the decrypted object
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	protected abstract Object decrypt(String value) throws GeneralSecurityException;

	/**
	 * {@inheritDoc}
	 */
	public Object assemble(final Serializable cached, final Object owner) throws HibernateException {
		if (cached == null) {
			return null;
		}
		return deepCopy(cached);
	}

	/**
	 * {@inheritDoc}
	 */
	public Object deepCopy(final Object value) throws HibernateException {
		return value;
	}

	/**
	 * {@inheritDoc}
	 */
	public Serializable disassemble(final Object value) throws HibernateException {
		if (value == null) {
			return null;
		}
		return (Serializable) deepCopy(value);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean equals(final Object x, final Object y) throws HibernateException {
		return EqualsHelper.equals(x, y);
	}

	/**
	 * {@inheritDoc}
	 */
	public int hashCode(final Object x) throws HibernateException {
		return x.hashCode();
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isMutable() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public Object nullSafeGet(final ResultSet rs, final String[] names, final Object owner)
			throws HibernateException, SQLException {
		final String text = rs.getString(names[0]);
		try {
			return rs.wasNull() || text.length() < 1 ? null : decrypt(text);
		}
		catch (final GeneralSecurityException e) {
			throw new HibernateException("Error decrypting object.", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void nullSafeSet(final PreparedStatement st, final Object value, final int index)
			throws HibernateException, SQLException {
		if (value == null) {
			st.setNull(index, Types.VARCHAR);
		}
		else {
			try {
				st.setString(index, encrypt(value));
			}
			catch (final GeneralSecurityException e) {
				throw new HibernateException("Error encrypting object.", e);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Object replace(final Object original, final Object target, final Object owner) throws HibernateException {
		return original;
	}

	/**
	 * {@inheritDoc}
	 */
	public int[] sqlTypes() {
		return sqlTypes;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setParameterValues(final Properties parameters) {
		lock.lock();
		try {
			configure(parameters);
			initializeIfNot();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Loads the encryptor and any other necessary instance variables.
	 * @param parameters the parameter values
	 */
	protected void configure(final Properties parameters) {
		encryptor = ConfigurerUtil.configureEncryptor(parameters);
	}

	private void initializeIfNot() {
		try {
			if (encryptor != null) {
				encryptor.initialize();
			}
		}
		catch (final GeneralSecurityException e) {
			throw new EncryptorConfigurationException("Error initializing cipher for Hibernate Usertype.", e);
		}
	}

	/**
	 * Returns the encryptor value.
	 *
	 * @return the encryptor.
	 */
	protected ValueEncryptorInterface<Encryptor> getEncryptor() {
		return encryptor;
	}

}
