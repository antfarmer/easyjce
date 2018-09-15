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
package org.antfarmer.ejce.test.db.encryptor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.test.db.AbstractDbTest;
import org.antfarmer.ejce.test.db.encryptor.bean.AbstractEncryptedValueBean;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public abstract class AbstractEncDbTest<T extends AbstractEncryptedValueBean<?>> extends AbstractDbTest {

	private final Class<T> beanClass = loadEntityClass();

	@Test
	public void test() throws IOException {

		final long id = getNextId();
		final Object[] value = new Object[1];

		try {
			execute(new HibernateCallback() {
				@SuppressWarnings("unchecked")
				@Override
				public void doInHibernate(final Session session) {
					final T bean = createBean();
					value[0] = bean.getValue();

					T sb = (T) session.get(beanClass, id);
					assertNull(sb);
					sb = bean;
					saveOrUpdate(sb);
					afterSave();

					sb = (T) session.get(beanClass, id + 1);
					assertNull(sb);
					sb = createEmptyBean();
					saveOrUpdate(sb);
				}
			});
		}
		finally {
			afterSave();
		}

		execute(new StatementCallback() {
			@Override
			protected void doStatment(final Statement stmt) throws SQLException {
				ResultSet rs = stmt.executeQuery("SELECT value FROM " + beanClass.getSimpleName() + " WHERE id = " + id);
				rs.next();
				try {
					assertEncrypted(value[0], rs);
				}
				catch (final IOException e) {
					throw new SQLException(e);
				}

				rs = stmt.executeQuery("SELECT value FROM " + beanClass.getSimpleName() + " WHERE id = " + (id + 1));
				rs.next();
				final String encValue = rs.getString(1);
				logger.info(encValue);
				assertTrue(rs.wasNull());
				assertNull(encValue);
			}
		});

		execute(new HibernateCallback() {
			@SuppressWarnings("unchecked")
			@Override
			public void doInHibernate(final Session session) {
				T sb = (T) session.get(beanClass, id);
				assertNotNull(sb);
				try {
					assertDecryptedEqual(value[0], sb);
				}
				catch (final SQLException e) {
					throw new HibernateException(e);
				}
				catch (final IOException e) {
					throw new HibernateException(e);
				}

				sb = (T) session.get(beanClass, id + 1);
				assertNotNull(sb);
				logger.info("{}", sb.getValue());
				assertNull(sb.getValue());
			}
		});
	}

	/**
	 * @return the next id to use for lookups
	 */
	protected long getNextId() {
		return 1;
	}

	/**
	 * Perform any clean up operations after saving the objects to the database
	 */
	protected void afterSave() {
		// nothing
	}

	/**
	 * Assert that the object value is now encrypted.
	 * @param value the value
	 * @param rs the {@link ResultSet}
	 * @throws SQLException SQLException
	 * @throws IOException IOException
	 */
	protected void assertEncrypted(final Object value, final ResultSet rs) throws SQLException, IOException {
		final String encValue = rs.getString(1);
		logger.info(encValue);
		assertNotEquals(value, encValue);
	}

	/**
	 * Assert that the decrypted object value is the same as original.
	 * @param value the decrypted value
	 * @param bean the bean
	 * @throws SQLException SQLException
	 * @throws IOException IOException
	 */
	protected void assertDecryptedEqual(final Object value, final T bean) throws SQLException, IOException {
		logger.info("{}", bean.getValue());
		assertEquals(value, bean.getValue());
	}

	/**
	 * @return a test bean
	 */
	protected abstract T createBean();

	/**
	 * @return a test bean with a null value
	 */
	protected abstract T createEmptyBean();

	/**
	 * Finds the type of the generic parameter T.
	 */
	@SuppressWarnings("unchecked")
	private Class<T> loadEntityClass() {
		Class<?> clazz = getClass();
		Type type = clazz.getGenericSuperclass();
		while (true) {
			if (type instanceof ParameterizedType) {
				final Type[] arguments = ((ParameterizedType)type).getActualTypeArguments();
				for (final Type argument : arguments) {
					if (argument instanceof Class
							&& AbstractEncryptedValueBean.class.isAssignableFrom((Class<?>)argument)) {
						return (Class<T>)argument;
					}
				}
				clazz = clazz.getSuperclass();
				type = clazz.getGenericSuperclass();
			}
			else {
				type = ((Class<?>)type).getGenericSuperclass();
			}
			if (type == Object.class) {
				throw new RuntimeException(
						"Could not find a Bean subclass parameterized type");
			}
		}
	}

}
