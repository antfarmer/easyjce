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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.antfarmer.common.hibernate.HibernateManager;
import org.antfarmer.ejce.test.db.encryptor.bean.BlobBean;
import org.hibernate.Hibernate;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class BlobBeanTest extends AbstractLobDbTest<BlobBean> {

	private File file;
	private InputStream streamValue;
	private long id = 1;

	@Override
	@Test
	public void test() throws IOException {

		final int[] sizes = {1000, 20 * 1024, 1200 * 1024};

		for (int i = 0; i < sizes.length; i++) {
			file = createRandomDataFile(sizes[i]);
			streamValue = new FileInputStream(file);
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
		final Blob encValue = rs.getBlob(1);
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
	protected void assertDecryptedEqual(final Object value, final BlobBean bean) throws SQLException, IOException {
		try {
			logger.info("Original Size: {}; New Size: {}", file.length(), bean.getValue().length());
			assertData(true, file, bean.getValue());
		}
		catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected BlobBean createBean() {
		return new BlobBean(Hibernate.getLobCreator(HibernateManager.instance().getSession()).createBlob(streamValue, file.length()));
	}

	@Override
	protected BlobBean createEmptyBean() {
		return new BlobBean(null);
	}

}
