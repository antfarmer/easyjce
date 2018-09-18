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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.sql.Blob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.antfarmer.common.util.ReflectionUtil;
import org.antfarmer.ejce.hibernate.AbstractHibernateType;
import org.antfarmer.ejce.hibernate.EncryptedBlobType;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.hibernate.HibernateException;
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
public class EncryptedBlobTypeTest extends AbstractEncryptedLobTypeTest<Blob> {

	private static final Charset CHARSET = Charset.forName("UTF-16");
	private static final byte[] TEST_VALUE = new byte[1000];

	static {
		RANDOM.nextBytes(TEST_VALUE);
	}

	public EncryptedBlobTypeTest() {
		super(CHARSET);
	}

	@Override
	protected Object getTestValue() {
		return TEST_VALUE;
	}

	@Override
	protected AbstractHibernateType createHibernateType() {
		return new EncryptedBlobType();
	}

	@Override
	protected EncryptThread createEncryptThread() {
		return new BlobEncryptThread();
	}

	@Test
	public void testGetSet() throws SQLException {
		final String[] columnNames = {"column1"};

		final SessionImplementor session = EasyMock.strictMock(SessionImplementor.class);
		final SessionFactoryImplementor factory = EasyMock.strictMock(SessionFactoryImplementor.class);
		final JdbcServices services = EasyMock.strictMock(JdbcServices.class);
		final LobCreator lobCreator = EasyMock.strictMock(LobCreator.class);

		final Blob bIn = EasyMock.strictMock(Blob.class);
		final Blob bOut = EasyMock.strictMock(Blob.class);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		EasyMock.expect(bIn.getBinaryStream()).andReturn(new ByteArrayInputStream(TEST_VALUE));
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
		EasyMock.expect(lobCreator.createBlob(TEST_VALUE)).andReturn(bOut);
		EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
		type.nullSafeGet(rs, columnNames, session, null);
		EasyMock.verify(bOut, lobCreator, services, factory, session, rs);
	}

	@Test
	public void testGetUnencrypted() throws SQLException {
		final String[] columnNames = {"column1"};

		final SessionImplementor session = EasyMock.strictMock(SessionImplementor.class);

		final Blob bOut = EasyMock.strictMock(Blob.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		final byte[] bytes = {' '};
		EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(bytes));
		EasyMock.expect(rs.wasNull()).andReturn(false);
		EasyMock.replay(bOut, session, rs);
		HibernateException ex = null;
		try {
			type.nullSafeGet(rs, columnNames, session, null);
		}
		catch (final HibernateException e) {
			ex = e;
		}
		assertNotNull(ex);
		assertSame(GeneralSecurityException.class, ex.getCause().getClass());
		assertTrue(ex.getCause().getMessage().contains("parameter spec data"));
		EasyMock.verify(bOut, session, rs);
	}

	@Test
	public void testGetSetBuffered() throws Exception {
		final String[] columnNames = {"column1"};

		final int maxMemBuffSize = ReflectionUtil.invokeMethod(type, "getMaxInMemoryBuffSize");
		final byte[] buff = new byte[maxMemBuffSize << 1];
		RANDOM.nextBytes(buff);

		final SessionImplementor session = EasyMock.strictMock(SessionImplementor.class);
		final SessionFactoryImplementor factory = EasyMock.strictMock(SessionFactoryImplementor.class);
		final JdbcServices services = EasyMock.strictMock(JdbcServices.class);
		final LobCreator lobCreator = EasyMock.strictMock(LobCreator.class);

		final Blob bIn = EasyMock.strictMock(Blob.class);
		final Blob bOut = EasyMock.strictMock(Blob.class);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		EasyMock.expect(bIn.getBinaryStream()).andReturn(new ByteArrayInputStream(buff));
		final Capture<BufferedInputStream> encCapt = EasyMock.newCapture();
		ps.setBinaryStream(EasyMock.eq(1), EasyMock.capture(encCapt), EasyMock.anyLong());
		EasyMock.expectLastCall();
		EasyMock.replay(bIn, ps);
		type.nullSafeSet(ps, bIn, 1, null);
		EasyMock.verify(bIn, ps);
		final BufferedInputStream enc = encCapt.getValue();

		EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(enc);
		EasyMock.expect(rs.wasNull()).andReturn(false);
		EasyMock.expect(session.getFactory()).andReturn(factory);
		EasyMock.expect(factory.getJdbcServices()).andReturn(services);
		EasyMock.expect(services.getLobCreator(session)).andReturn(lobCreator);
		final Capture<BufferedInputStream> decCapt = EasyMock.newCapture();
		EasyMock.expect(lobCreator.createBlob(EasyMock.capture(decCapt), EasyMock.eq((long) buff.length))).andReturn(bOut);
		EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
		type.nullSafeGet(rs, columnNames, session, null);
		EasyMock.verify(bOut, lobCreator, services, factory, session, rs);
	}

	private class BlobEncryptThread extends EncryptThread {

		final String[] columnNames = {"column1"};

		final SessionImplementor session = EasyMock.strictMock(SessionImplementor.class);
		final SessionFactoryImplementor factory = EasyMock.strictMock(SessionFactoryImplementor.class);
		final JdbcServices services = EasyMock.strictMock(JdbcServices.class);
		final LobCreator lobCreator = EasyMock.strictMock(LobCreator.class);

		final Blob bIn = EasyMock.strictMock(Blob.class);
		final Blob bOut = EasyMock.strictMock(Blob.class);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		/**
		 * {@inheritDoc}
		 */
		@Override
		protected void doIteration() throws Throwable {
			EasyMock.expect(bIn.getBinaryStream()).andReturn(new ByteArrayInputStream(TEST_VALUE));
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
			EasyMock.expect(lobCreator.createBlob(TEST_VALUE)).andReturn(bOut);
			EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
			type.nullSafeGet(rs, columnNames, session, null);
			EasyMock.verify(bOut, lobCreator, services, factory, session, rs);

			EasyMock.reset(bIn, ps, bOut, lobCreator, services, factory, session, rs);
		}

	}

}
