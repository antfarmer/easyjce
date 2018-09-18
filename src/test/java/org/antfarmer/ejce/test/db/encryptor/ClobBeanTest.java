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

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.antfarmer.common.hibernate.HibernateManager;
import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.ejce.test.db.encryptor.bean.ClobBean;
import org.hibernate.Hibernate;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class ClobBeanTest extends AbstractLobDbTest<ClobBean> {

	private static final int THREAD_COUNT = 20;
	private static final int THREAD_ITERATIONS = 25;

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

	private ClobBean createBean(final Reader reader, final long length) {
		return new ClobBean(Hibernate.getLobCreator(HibernateManager.instance().getSession()).createClob(reader, length));
	}

	@Override
	protected ClobBean createBean() {
		return createBean(streamValue, file.length());
	}

	@Override
	protected ClobBean createEmptyBean() {
		return new ClobBean(null);
	}

	@Test
	public void testThreadsWithCompressedStream() throws Throwable {

		Object value = null;

		file = createRandomDataFile(9000, true);

		// write multi-threaded
		final LobWriteThread[] writeThreads = new LobWriteThread[THREAD_COUNT];
		for (int i = 0; i < writeThreads.length; i++) {
			writeThreads[i] = new LobWriteThread();
			writeThreads[i].start();
		}
		// wait and check for errors
		for (int i = 0; i < writeThreads.length; i++) {
			writeThreads[i].join();
			value = writeThreads[i].value;

			if (writeThreads[i].throwable != null) {
				throw writeThreads[i].throwable;
			}
		}

		// read multi-threaded
		final LobReadThread[] readThreads = new LobReadThread[THREAD_COUNT];
		for (int i = 0; i < readThreads.length; i++) {
			readThreads[i] = new LobReadThread(i, value);
			readThreads[i].start();
		}
		// wait and check for errors
		for (int i = 0; i < readThreads.length; i++) {
			readThreads[i].join();

			if (readThreads[i].throwable != null) {
				throw readThreads[i].throwable;
			}
		}
	}

	private class LobWriteThread extends Thread {
		private Throwable throwable;
		private Object value;

		@Override
		public void run() {
			try {
				for (int i = 0; i < THREAD_ITERATIONS; i++) {
					saveToDb();
				}
			}
			catch (final Throwable e) {
				throwable = e;
			}
		}

		private void saveToDb() throws FileNotFoundException {
			final FileReader streamValue = new FileReader(file);
			try {
				execute(new HibernateCallback() {
					@Override
					public void doInHibernate(final Session session) {
						final ClobBean bean = createBean(streamValue, file.length());
						value = bean.getValue();
						saveOrUpdate(bean);
					}
				});
			}
			finally {
				close(streamValue);
			}
		}

	}

	private class LobReadThread extends Thread {
		private final Object value;
		private Throwable throwable;
		private final long idStart;

		public LobReadThread(final int idx, final Object value) {
			this.value = value;
			idStart = 1 + (idx * THREAD_ITERATIONS);
		}

		@Override
		public void run() {
			try {
				for (int i = 0; i < THREAD_ITERATIONS; i++) {
					readAndVerifyValue(i);
				}
			}
			catch (final Throwable e) {
				throwable = e;
			}
		}

		private void readAndVerifyValue(final int i) {
			execute(new HibernateCallback() {
				@Override
				public void doInHibernate(final Session session) {
					final long id = idStart + i;
					final ClobBean sb = (ClobBean) session.get(beanClass, id);
					assertNotNull(sb);
					try {
						assertDecryptedEqual(value, sb);
						System.out.println("Found same value for id: " + id);
					}
					catch (final SQLException e) {
						throw new HibernateException(e);
					}
					catch (final IOException e) {
						throw new HibernateException(e);
					}
				}
			});
		}
	}

}
