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
package org.antfarmer.ejce.test.db.password;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.password.ConfigurablePasswordEncoder;
import org.antfarmer.ejce.password.PasswordEncoderStore;
import org.antfarmer.ejce.test.db.AbstractDbTest;
import org.antfarmer.ejce.test.db.password.bean.AbstractPasswordBean;
import org.hibernate.Session;
import org.junit.After;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public abstract class AbstractPasswordBeanTest<T extends AbstractPasswordBean> extends AbstractDbTest {

	private final Class<T> beanClass = loadEntityClass();

	@Test
	public void test() {

		final long id = 1;
		final String password = "pAssW0rd";

		execute(new HibernateCallback() {
			@SuppressWarnings("unchecked")
			@Override
			public void doInHibernate(final Session session) {
				T sb = (T) session.get(beanClass, id);
				assertNull(sb);
				sb = createBean(password);
				saveOrUpdate(sb);

				sb = (T) session.get(beanClass, id + 1);
				assertNull(sb);
				sb = createBean(null);
				saveOrUpdate(sb);
			}
		});

		execute(new StatementCallback() {
			@Override
			protected void doStatment(final Statement stmt) throws SQLException {
				final ResultSet rs = stmt.executeQuery("SELECT password FROM " + beanClass.getSimpleName() + " WHERE id = " + id);
				rs.next();
				final String hashValue = rs.getString(1);
				logger.info(hashValue);
				assertNotEquals(password, hashValue);
			}
		});


		execute(new HibernateCallback() {
			@SuppressWarnings("unchecked")
			@Override
			public void doInHibernate(final Session session) {
				T sb = (T) session.get(beanClass, id);
				assertNotNull(sb);
				final ConfigurablePasswordEncoder encoder = PasswordEncoderStore.get(sb.getStoreExportKey());
				logger.info(sb.getPassword());
				assertNotEquals(password, sb.getPassword());
				assertTrue(encoder.matches(password, sb.getPassword()));

				sb = (T) session.get(beanClass, id + 1);
				assertNotNull(sb);
				logger.info(sb.getPassword());
				assertNull(password, sb.getPassword());
			}
		});
	}

	protected abstract T createBean(String password);

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
							&& AbstractPasswordBean.class.isAssignableFrom((Class<?>)argument)) {
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

	@After
	public void after() {
		PasswordEncoderStore.clear();
	}

}
