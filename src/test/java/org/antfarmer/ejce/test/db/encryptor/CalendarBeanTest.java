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

import java.io.IOException;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.TimeZone;

import org.antfarmer.ejce.test.db.encryptor.bean.CalendarBean;

/**
 * @author Ameer Antar
 */
public class CalendarBeanTest extends AbstractEncDbTest<CalendarBean> {

	private final TimeZone tz = TimeZone.getTimeZone("GMT");
	private final Calendar value = Calendar.getInstance(tz);

	@Override
	protected CalendarBean createBean() {
		return new CalendarBean(value);
	}

	@Override
	protected CalendarBean createEmptyBean() {
		return new CalendarBean(null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void assertDecryptedEqual(final Object value, final CalendarBean bean) throws SQLException, IOException {
		super.assertDecryptedEqual(value, bean);
		assertEquals(tz, bean.getValue().getTimeZone());
	}

}
