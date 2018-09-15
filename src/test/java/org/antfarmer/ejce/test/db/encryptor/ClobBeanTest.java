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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.antfarmer.common.hibernate.HibernateManager;
import org.antfarmer.ejce.test.db.encryptor.bean.ClobBean;
import org.hibernate.Hibernate;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class ClobBeanTest extends AbstractLobDbTest<ClobBean> {

	private File file;
	private Reader streamValue;
	private long id = 1;

	@Override
	@Test
	public void test() throws IOException {

		final int[] sizes = {1000, 20 * 1024, 1200 * 1024};

		for (int i = 0; i < sizes.length; i++) {
			file = createRandomDataFile(sizes[i], true);
			streamValue = new FileReader(file);
			super.test();
			id += 2;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void afterSave() {
		close(streamValue);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected long getNextId() {
		return id;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void assertEncrypted(final Object value, final ResultSet rs) throws SQLException, IOException {
		final Clob encValue = rs.getClob(1);
		logger.info("Original Size: {}; Enc Size: {}", file.length(), encValue.length());
		try {
			assertData(false, file, encValue);
		}
		catch (final IOException e) {
			throw new SQLException(e.getMessage(), e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void assertDecryptedEqual(final Object value, final ClobBean bean) throws SQLException, IOException {
		try {
			logger.info("Original Size: {}; New Size: {}", file.length(), bean.getValue().length());
			assertData(true, file, bean.getValue());
		}
		catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected ClobBean createBean() {
		return new ClobBean(Hibernate.getLobCreator(HibernateManager.instance().getSession()).createClob(streamValue, file.length()));
	}

	@Override
	protected ClobBean createEmptyBean() {
		return new ClobBean(null);
	}

}
