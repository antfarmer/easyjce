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

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Random;

import org.antfarmer.common.ApplicationSettings;
import org.antfarmer.common.Loggable;
import org.antfarmer.common.hibernate.HibernateManager;
import org.antfarmer.common.hibernate.HibernateManager.HibernateCallback;
import org.antfarmer.common.hibernate.HibernateUtil;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.internal.SessionImpl;
import org.hibernate.tool.hbm2ddl.SchemaExport;
import org.junit.Before;
import org.junit.BeforeClass;

/**
 * Abstract function database test class.
 * @author Ameer Antar
 */
public abstract class AbstractDbTest extends Loggable {

	private static final String TEST_HIBERNATE_PROP_PATH = "test/hibernate.test.properties";

	private static final boolean EXPORT_SCRIPT = false;

	protected static final Random RANDOM = new Random();

	@BeforeClass
	public static void loadProps() {
		ApplicationSettings.loadSettings(AbstractDbTest.class, ApplicationSettings.PROP_KEY_HIBERNATE_PROP_PATH, TEST_HIBERNATE_PROP_PATH);
	}

	@Before
	public void before() {
		logger.info("Starting {}", getClass().getSimpleName());
		loadProps();
		exportDb();
	}

	private void exportDb() {
		execute(new HibernateCallback() {
			@Override
			public void doInHibernate(final Session session) {
				logger.info("Exporting DB...");
				new SchemaExport(HibernateUtil.createConfiguration(), ((SessionImpl)session).connection()).create(EXPORT_SCRIPT, true);
				logger.info("DB exported successfully");
			}
		});
	}

	/**
	 * Executes the given callback in the context of a Hibernate session.
	 *
	 * @param callback
	 */
	protected void execute(final HibernateCallback callback) {
		HibernateManager.instance().execute(callback);
	}

	/**
	 * Executes the given callback in the context of a Hibernate session, providing a {@link Connection}
	 * to the db for executing SQL.
	 *
	 * @param callback
	 */
	protected void execute(final SqlCallback callback) {
		execute(new HibernateCallback() {
			@Override
			public void doInHibernate(final Session session) {
				final Connection connection = ((SessionImpl) session).connection();
				try {
					callback.doInConnection(connection);
				}
				catch (final SQLException e) {
					throw new HibernateException(e);
				}
			}
		});
	}

	/**
	 * Saves or updates the given bean.
	 * @param bean
	 */
	protected void saveOrUpdate(final Object bean) {
		HibernateManager.instance().getSession().saveOrUpdate(bean);
	}

	/**
	 * Callback for executing SQL, providing a {@link Connection}.
	 * @author Ameer Antar
	 */
	protected static interface SqlCallback {
		/**
		 * Executes SQL given a {@link Connection}.
		 * @param connection
		 * @throws SQLException
		 */
		void doInConnection(Connection connection) throws SQLException;
	}

	/**
	 * Callback for executing an SQL, providing a {@link Statement}.
	 * @author Ameer Antar
	 */
	protected static abstract class StatementCallback implements SqlCallback {

		/**
		 * {@inheritDoc}
		 */
		@Override
		public final void doInConnection(final Connection connection) throws SQLException {
			final Statement stmt = connection.createStatement();
			try {
				doStatment(stmt);
			}
			finally {
				stmt.close();
			}
		}

		/**
		 * Executes SQL using the given {@link Statement}.
		 * @param stmt
		 * @throws SQLException
		 */
		protected abstract void doStatment(Statement stmt) throws SQLException;
	}
}
