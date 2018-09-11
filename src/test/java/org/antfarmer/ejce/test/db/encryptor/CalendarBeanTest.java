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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.TimeZone;

import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.test.db.AbstractDbTest;
import org.antfarmer.ejce.test.db.encryptor.bean.CalendarBean;
import org.hibernate.Session;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class CalendarBeanTest extends AbstractDbTest {

	private static final Class<?> BEAN_CLASS = CalendarBean.class;

	@Test
	public void test() {

		final long id = 1;
		final TimeZone tz = TimeZone.getTimeZone("GMT");
		final Calendar value = Calendar.getInstance(tz);

		execute(new HibernateCallback() {
			@Override
			public void doInHibernate(final Session session) {
				CalendarBean sb = (CalendarBean) session.get(BEAN_CLASS, id);
				assertNull(sb);
				sb = new CalendarBean(value);
				saveOrUpdate(sb);
			}
		});

		execute(new StatementCallback() {
			@Override
			protected void doStatment(final Statement stmt) throws SQLException {
				final ResultSet rs = stmt.executeQuery("SELECT value FROM " + BEAN_CLASS.getSimpleName() + " WHERE id = " + id);
				rs.next();
				final String encValue = rs.getString(1);
				logger.info(encValue);
				assertNotEquals(value, encValue);
			}
		});

		execute(new HibernateCallback() {
			@Override
			public void doInHibernate(final Session session) {
				final CalendarBean sb = (CalendarBean) session.get(BEAN_CLASS, id);
				assertNotNull(sb);
				logger.info("{}", sb.getValue());
				assertEquals(tz, sb.getValue().getTimeZone());
				assertEquals(value, sb.getValue());
			}
		});
	}

}
