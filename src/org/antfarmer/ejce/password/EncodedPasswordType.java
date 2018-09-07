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

import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantLock;

import org.antfarmer.ejce.util.ConfigurerUtil;
import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SessionImplementor;
import org.hibernate.internal.util.compare.EqualsHelper;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.usertype.UserType;

/**
 * Hibernate UserType class which encodes password values transparently using a one-way hashing algorithm.
 * This ensures data is stored in it's hashed form in persistent storage. Values returned in the application
 * will be that of the hashed/encoded form.
 *
 * @author Ameer Antar
 * @version 1.1
 */
public class EncodedPasswordType implements UserType, ParameterizedType {

	private static final int[] sqlTypes = new int[] {Types.VARCHAR};

	private ConfigurablePasswordEncoder pswdEncoder;

	private final ReentrantLock lock = new ReentrantLock();

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
		return rs.wasNull() || text.length() < 1 ? null : text;
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
		else if (value instanceof CharSequence) {
			st.setString(index, pswdEncoder.encode((CharSequence) value));
		}
		else {
			throw new HibernateException("Cannot encode password object of type: " + value.getClass().getName());
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
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Loads the password encoder and any other necessary instance variables.
	 * @param parameters the parameter values
	 */
	protected void configure(final Properties parameters) {
		if (pswdEncoder != null) {
			throw new IllegalStateException("This type can only be configured once");
		}
		pswdEncoder = ConfigurerUtil.configurePswdEncoder(parameters);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Class<?> returnedClass() {
		return String.class;
	}

}
