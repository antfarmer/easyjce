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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.test.db.bean.TextBean;
import org.antfarmer.ejce.util.StreamUtil;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class TextBeanTest extends AbstractLobDbTest {

	private static final Class<?> BEAN_CLASS = TextBean.class;

	@Test
	public void test() throws IOException {

		final int[] sizes = {1000, 20 * 1024, 520 * 1024};

		for (int i = 0; i < sizes.length; i++) {
			final File file = createRandomDataFile(sizes[i], true);

			final long id = i + 1;
			final InputStream streamValue = new FileInputStream(file);

			try {
				execute(new HibernateCallback() {
					@Override
					public void doInHibernate(final Session session) {
						TextBean sb = (TextBean) session.get(BEAN_CLASS, id);
						assertNull(sb);
						try {
							sb = new TextBean(new String(StreamUtil.streamToBytes(streamValue)));
							saveOrUpdate(sb);
						}
						catch (final IOException e) {
							throw new HibernateException(e.getMessage(), e);
						}
					}
				});
			}
			finally {
				close(streamValue);
			}

			execute(new StatementCallback() {
				@Override
				void doStatment(final Statement stmt) throws SQLException {
					final ResultSet rs = stmt.executeQuery("SELECT value FROM " + BEAN_CLASS.getSimpleName() + " WHERE id = " + id);
					rs.next();
					final Clob encValue = rs.getClob(1);
					logger.info("Original Size: {}; Enc Size: {}", file.length(), encValue.length());
					try {
						assertData(false, file, encValue);
					}
					catch (final IOException e) {
						throw new SQLException(e.getMessage(), e);
					}
				}
			});

			execute(new HibernateCallback() {
				@Override
				public void doInHibernate(final Session session) {
					final TextBean sb = (TextBean) session.get(BEAN_CLASS, id);
					assertNotNull(sb);
					try {
						logger.info("Original Size: {}; New Size: {}", file.length(), sb.getValue().length());
						assertEquals(new String(StreamUtil.streamToBytes(new FileInputStream(file))), sb.getValue());
					}
					catch (final IOException e) {
						throw new RuntimeException(e);
					}
				}
			});
		}
	}

}
