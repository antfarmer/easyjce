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
package org.antfarmer.ejce.test.db;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;

import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.test.db.bean.ClobBean;
import org.antfarmer.ejce.util.StreamUtil;
import org.hibernate.Hibernate;
import org.hibernate.Session;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class ClobBeanTest extends AbstractDbTest {

	private static final Class<?> BEAN_CLASS = ClobBean.class;

	@Test
	public void test() {

		final int[] sizes = {1000, 20 * 1024, 800 * 1024};

		for (int i = 0; i < sizes.length; i++) {
			final long id = i + 1;
			final byte[] value = new byte[sizes[i]];
			for (int j = 0; j < value.length; j++) {
				value[j] = (byte) (33 + RANDOM.nextInt(94));
			}

			execute(new HibernateCallback() {
				@Override
				public void doInHibernate(final Session session) {
					ClobBean sb = (ClobBean) session.get(BEAN_CLASS, id);
					assertNull(sb);
					sb = new ClobBean(Hibernate.getLobCreator(session).createClob(new String(value)));
					saveOrUpdate(sb);
				}
			});

			execute(new StatementCallback() {
				@Override
				void doStatment(final Statement stmt) throws SQLException {
					final ResultSet rs = stmt.executeQuery("SELECT value FROM " + BEAN_CLASS.getSimpleName() + " WHERE id = " + id);
					rs.next();
					final byte[] encValue = rs.getBytes(1);
					logger.info("Original Size: {}; Enc Size: {}", value.length, encValue.length);
					assertFalse(Arrays.equals(value, encValue));
				}
			});

			execute(new HibernateCallback() {
				@Override
				public void doInHibernate(final Session session) {
					final ClobBean sb = (ClobBean) session.get(BEAN_CLASS, id);
					assertNotNull(sb);
					byte[] bytes;
					try {
						logger.info("Original Size: {}; New Size: {}", value.length, sb.getValue().length());
						bytes = StreamUtil.streamToBytes(sb.getValue().getAsciiStream());
						assertArrayEquals(value, bytes);
					}
					catch (final Exception e) {
						throw new RuntimeException(e);
					}
				}
			});
		}
	}

}
