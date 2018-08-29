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

import java.io.Serializable;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
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
import org.hibernate.engine.spi.SessionImplementor;
import org.hibernate.internal.util.compare.EqualsHelper;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.usertype.UserType;

/**
 * Abstract Hibernate UserType class which encrypts and decrypts values transparently. This ensures
 * data is stored in it's encrypted form in persistent storage, while not affecting it's real value
 * in the application.
 *
 * @author Ameer Antar
 * @version 1.2
 */
public abstract class AbstractHibernateType implements UserType, ParameterizedType {

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	private static final int[] sqlTypes = new int[] {Types.VARCHAR};

	private ValueEncryptorInterface<Encryptor> encryptor;

	private Charset charset;

	static final SecureRandom random = new SecureRandom();

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
	@Override
	public Object assemble(final Serializable cached, final Object owner) throws HibernateException {
		if (cached == null) {
			return null;
		}
		return deepCopy(cached);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Object deepCopy(final Object value) throws HibernateException {
		return value;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Serializable disassemble(final Object value) throws HibernateException {
		if (value == null) {
			return null;
		}
		return (Serializable) deepCopy(value);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(final Object x, final Object y) throws HibernateException {
		return EqualsHelper.equals(x, y);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode(final Object x) throws HibernateException {
		return x.hashCode();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isMutable() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Object nullSafeGet(final ResultSet rs, final String[] names, final SessionImplementor session, final Object owner)
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
	@Override
	public void nullSafeSet(final PreparedStatement st, final Object value, final int index, final SessionImplementor session)
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
	@Override
	public Object replace(final Object original, final Object target, final Object owner) throws HibernateException {
		return original;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int[] sqlTypes() {
		return sqlTypes;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
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
		setCharset(parameters);
	}

	protected void setCharset(final Properties parameters) {
		// load charset
		final String value = parameters.getProperty(ConfigurerUtil.KEY_CHARSET);
		if (value != null) {
			charset = Charset.forName(value.trim());
		}
		else {
			charset = DEFAULT_CHARSET;
		}
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

	/**
	 * Returns the charset.
	 * @return the charset
	 */
	protected Charset getCharset() {
		return charset;
	}

}
