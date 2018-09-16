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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.sql.Clob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Random;

import org.antfarmer.ejce.hibernate.EncryptedClobType;
import org.antfarmer.ejce.test.hibernate.util.TypeUtil;
import org.antfarmer.ejce.util.StreamUtil;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.hibernate.engine.jdbc.LobCreator;
import org.hibernate.engine.jdbc.spi.JdbcServices;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.engine.spi.SessionImplementor;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedClobTypeTest extends EncryptedClobType {

	private static final Charset CHARSET = Charset.forName("UTF-8");
	private static String TEST_VALUE;
	private static final Random random = new Random();

	static {
		final byte[] content = new byte[1000];
		random.nextBytes(content);
		TEST_VALUE = new String(content, CHARSET);
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 *
	 */
	@Before
	public void init() throws GeneralSecurityException {
		setParameterValues(TypeUtil.prepareTestEncryptorParameters(CHARSET));
	}

	@Test
	public void test() throws GeneralSecurityException, IOException {

		final InputStream enc = encryptStream(new ByteArrayInputStream(TEST_VALUE.getBytes(CHARSET)));
		final InputStream dec = decryptStream(enc);
		assertEquals(TEST_VALUE, new String(StreamUtil.streamToBytes(dec), CHARSET));

		assertSame(Clob.class, returnedClass());
	}

	/**
	 * @throws Exception Exception
	 */
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

		EasyMock.expect(bIn.getAsciiStream()).andReturn(new ByteArrayInputStream(TEST_VALUE.getBytes(CHARSET)));
		final Capture<byte[]> encBytesCapt = EasyMock.newCapture();
		ps.setBytes(EasyMock.eq(1), EasyMock.capture(encBytesCapt));
		EasyMock.expectLastCall();
		EasyMock.replay(bIn, ps);
		nullSafeSet(ps, bIn, 1, null);
		EasyMock.verify(bIn, ps);
		final byte[] enc = encBytesCapt.getValue();

		EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(enc));
		EasyMock.expect(rs.wasNull()).andReturn(false);
		EasyMock.expect(session.getFactory()).andReturn(factory);
		EasyMock.expect(factory.getJdbcServices()).andReturn(services);
		EasyMock.expect(services.getLobCreator(session)).andReturn(lobCreator);
		EasyMock.expect(lobCreator.createClob(TEST_VALUE)).andReturn(bOut);
		EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
		nullSafeGet(rs, columnNames, session, null);
		EasyMock.verify(bOut, lobCreator, services, factory, session, rs);
	}

	@Test
	public void testThreadSafety() throws Throwable {
		final int num = 25;
		final EncryptThread[] threads = new EncryptThread[num];
		for (int i=0; i<num; i++) {
			threads[i] = new EncryptThread();
			threads[i].start();
		}
		for (int i=0; i<num; i++) {
			threads[i].join();
			if (threads[i].exception != null) {
				throw threads[i].exception;
			}
		}
	}

	private class EncryptThread extends Thread {
		private Throwable exception;

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
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<50; i++) {
					EasyMock.expect(bIn.getAsciiStream()).andReturn(new ByteArrayInputStream(TEST_VALUE.getBytes(CHARSET)));
					final Capture<byte[]> encBytesCapt = EasyMock.newCapture();
					ps.setBytes(EasyMock.eq(1), EasyMock.capture(encBytesCapt));
					EasyMock.expectLastCall();
					EasyMock.replay(bIn, ps);
					nullSafeSet(ps, bIn, 1, null);
					EasyMock.verify(bIn, ps);
					final byte[] enc = encBytesCapt.getValue();

					EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(enc));
					EasyMock.expect(rs.wasNull()).andReturn(false);
					EasyMock.expect(session.getFactory()).andReturn(factory);
					EasyMock.expect(factory.getJdbcServices()).andReturn(services);
					EasyMock.expect(services.getLobCreator(session)).andReturn(lobCreator);
					EasyMock.expect(lobCreator.createClob(TEST_VALUE)).andReturn(bOut);
					EasyMock.replay(bOut, lobCreator, services, factory, session, rs);
					nullSafeGet(rs, columnNames, session, null);
					EasyMock.verify(bOut, lobCreator, services, factory, session, rs);

					EasyMock.reset(bIn, ps, bOut, lobCreator, services, factory, session, rs);
				}
			}
			catch (final Throwable e) {
				exception = e;
				e.printStackTrace();
			}
		}

	}

}
