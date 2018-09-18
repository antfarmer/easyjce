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
package org.antfarmer.ejce.test.hibernate;

import java.io.ByteArrayInputStream;
import java.sql.Clob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.antfarmer.ejce.hibernate.AbstractHibernateType;
import org.antfarmer.ejce.hibernate.EncryptedClobType;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.hibernate.engine.jdbc.LobCreator;
import org.hibernate.engine.jdbc.spi.JdbcServices;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.engine.spi.SessionImplementor;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedClobTypeTest extends AbstractEncryptedLobTypeTest<Clob> {

	private static final byte[] TEST_VALUE;
	private static final String TEXT_VALUE;

	static {
		TEST_VALUE = new byte[1000];
		nextAsciiBytes(TEST_VALUE);
		TEXT_VALUE = new String(TEST_VALUE, UTF8);
	}

	public EncryptedClobTypeTest() {
		super(UTF8);
	}

	@Override
	protected Object getTestValue() {
		return TEST_VALUE;
	}

	@Override
	protected AbstractHibernateType createHibernateType() {
		return new EncryptedClobType();
	}

	@Override
	protected EncryptThread createEncryptThread() {
		return new ClobEncryptThread();
	}

	@Test
	public void testGetSet() throws Exception {
		final String[] columnNames = {"column1"};

		final SessionImplementor session = EasyMock.strictMock(SessionImplementor.class);
		final SessionFactoryImplementor factory = EasyMock.strictMock(SessionFactoryImplementor.class);
		final JdbcServices services = EasyMock.strictMock(JdbcServices.class);
		final LobCreator lobCreator = EasyMock.strictMock(LobCreator.class);

		final Clob bIn = EasyMock.strictMock(Clob.class);
		final Clob bOut = EasyMock.strictMock(Clob.class);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		EasyMock.expect(bIn.getAsciiStream()).andReturn(new ByteArrayInputStream(TEST_VALUE));
		final Capture<byte[]> encBytesCapt = EasyMock.newCapture();
		ps.setBytes(EasyMock.eq(1), EasyMock.capture(encBytesCapt));
		EasyMock.expectLastCall();
		EasyMock.replay(bIn, ps);
		type.nullSafeSet(ps, bIn, 1, null);
		EasyMock.verify(bIn, ps);
		final byte[] enc = encBytesCapt.getValue();

		EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(enc));
		EasyMock.expect(rs.wasNull()).andReturn(false);
		EasyMock.expect(session.getFactory()).andReturn(factory);
		EasyMock.expect(factory.getJdbcServices()).andReturn(services);
		EasyMock.expect(services.getLobCreator(session)).andReturn(lobCreator);
		EasyMock.expect(lobCreator.createClob(TEXT_VALUE)).andReturn(bOut);
		EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
		type.nullSafeGet(rs, columnNames, session, null);
		EasyMock.verify(bOut, lobCreator, services, factory, session, rs);
	}

	private class ClobEncryptThread extends EncryptThread {

		final String[] columnNames = {"column1"};

		final SessionImplementor session = EasyMock.strictMock(SessionImplementor.class);
		final SessionFactoryImplementor factory = EasyMock.strictMock(SessionFactoryImplementor.class);
		final JdbcServices services = EasyMock.strictMock(JdbcServices.class);
		final LobCreator lobCreator = EasyMock.strictMock(LobCreator.class);

		final Clob bIn = EasyMock.strictMock(Clob.class);
		final Clob bOut = EasyMock.strictMock(Clob.class);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		/**
		 * {@inheritDoc}
		 */
		@Override
		protected void doIteration() throws Throwable {
			EasyMock.expect(bIn.getAsciiStream()).andReturn(new ByteArrayInputStream(TEST_VALUE));
			final Capture<byte[]> encBytesCapt = EasyMock.newCapture();
			ps.setBytes(EasyMock.eq(1), EasyMock.capture(encBytesCapt));
			EasyMock.expectLastCall();
			EasyMock.replay(bIn, ps);
			type.nullSafeSet(ps, bIn, 1, null);
			EasyMock.verify(bIn, ps);
			final byte[] enc = encBytesCapt.getValue();

			EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(enc));
			EasyMock.expect(rs.wasNull()).andReturn(false);
			EasyMock.expect(session.getFactory()).andReturn(factory);
			EasyMock.expect(factory.getJdbcServices()).andReturn(services);
			EasyMock.expect(services.getLobCreator(session)).andReturn(lobCreator);
			EasyMock.expect(lobCreator.createClob(TEXT_VALUE)).andReturn(bOut);
			EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
			type.nullSafeGet(rs, columnNames, session, null);
			EasyMock.verify(bOut, lobCreator, services, factory, session, rs);

			EasyMock.reset(bIn, ps, bOut, lobCreator, services, factory, session, rs);
		}

	}

}
