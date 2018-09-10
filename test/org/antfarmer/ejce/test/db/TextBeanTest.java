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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.test.db.bean.TextBean;
import org.hibernate.Session;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class TextBeanTest extends AbstractDbTest {

	private static final Class<?> BEAN_CLASS = TextBean.class;

	@Test
	public void test() {

		final int[] sizes = {1000, 20 * 1024, 800 * 1024};

		for (int i = 0; i < sizes.length; i++) {
			final long id = i + 1;
			final byte[] value = new byte[sizes[i]];
			for (int j = 0; j < value.length; j++) {
				value[j] = (byte) (33 + RANDOM.nextInt(94));
			}
			final String val = new String(value);

			execute(new HibernateCallback() {
				@Override
				public void doInHibernate(final Session session) {
					TextBean sb = (TextBean) session.get(BEAN_CLASS, id);
					assertNull(sb);
					sb = new TextBean(val);
					saveOrUpdate(sb);
				}
			});

			execute(new StatementCallback() {
				@Override
				void doStatment(final Statement stmt) throws SQLException {
					final ResultSet rs = stmt.executeQuery("SELECT value FROM " + BEAN_CLASS.getSimpleName() + " WHERE id = " + id);
					rs.next();
					final String encValue = rs.getString(1);
					logger.info("Original Size: {}; Enc Size: {}", value.length, encValue.length());
					assertNotEquals(val, encValue);
				}
			});

			execute(new HibernateCallback() {
				@Override
				public void doInHibernate(final Session session) {
					final TextBean sb = (TextBean) session.get(BEAN_CLASS, id);
					assertNotNull(sb);
					try {
						logger.info("Original Size: {}; New Size: {}", value.length, sb.getValue().length());
						assertEquals(val, sb.getValue());
					}
					catch (final Exception e) {
						throw new RuntimeException(e);
					}
				}
			});
		}
	}

}
