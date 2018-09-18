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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Properties;

import org.antfarmer.common.util.ReflectionUtil;
import org.antfarmer.ejce.hibernate.AbstractHibernateType;
import org.antfarmer.ejce.hibernate.EncryptedTextType;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.antfarmer.ejce.util.StreamUtil;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.hibernate.engine.spi.SessionImplementor;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedTextTypeTest extends AbstractEncryptedLobTypeTest<String> {

	private static final byte[] TEST_VALUE;
	private static final String TEXT_VALUE;

	static {
		TEST_VALUE = new byte[10000];
		nextAsciiBytes(TEST_VALUE);
		TEXT_VALUE = new String(TEST_VALUE, UTF8);
	}

	public EncryptedTextTypeTest() {
		super(UTF8, createProps());
	}

	private static Properties createProps() {
		final Properties props = new Properties();
		props.put(ConfigurerUtil.KEY_COMPRESS_LOB, true);
		return props;
	}

	@Override
	protected Object getTestValue() {
		return TEST_VALUE;
	}

	@Override
	protected AbstractHibernateType createHibernateType() {
		return new EncryptedTextType();
	}

	@Override
	protected EncryptThread createEncryptThread() {
		return new TextEncryptThread();
	}

	protected int getStreamBuffSize() throws Exception {
		return ReflectionUtil.invokeMethod(type, "getStreamBuffSize");
	}

	protected int getMaxInMemoryBuffSize() throws Exception {
		return ReflectionUtil.invokeMethod(type, "getMaxInMemoryBuffSize");
	}

	protected Object streamToLob(final InputStream is, final SessionImplementor session) throws Exception {
		return ReflectionUtil.invokeMethod(type, "streamToLob", InputStream.class, SessionImplementor.class, is, session);
	}

	protected void setStream(final PreparedStatement st, final int index, final InputStream is) throws Exception {
		ReflectionUtil.invokeMethod(type, "setStream", PreparedStatement.class, int.class, InputStream.class, st, index, is);
	}

	@Test
	public void testUnicode() throws GeneralSecurityException, IOException {
		final String o = "\u0627\u0645\u064a\u0631";

		// can run with '-Dfile.encoding=ISO-8859-1'
		System.out.println(Charset.defaultCharset());
		System.out.println(o);

		final InputStream enc = encryptStream(new ByteArrayInputStream(o.getBytes(UTF8)));
		final InputStream dec = decryptStream(enc);
		final String decString = new String(StreamUtil.streamToBytes(dec), UTF8);
		System.out.println(decString);
		assertEquals(o, decString);
	}

	@Test
	public void testLobToStream() throws Exception {
		final InputStream is = ReflectionUtil.invokeMethod(type, "lobToStream", Object.class, new String(TEST_VALUE, UTF8));
		assertEquals(TEXT_VALUE, new String(StreamUtil.streamToBytes(is), UTF8));
	}

	@Test
	public void testCreateLob() throws Exception {
		String lob = (String) ReflectionUtil.invokeMethod(type, "createLob",
				byte[].class, SessionImplementor.class, TEST_VALUE, null);
		assertEquals(TEXT_VALUE, lob);

		final ByteArrayInputStream bais = new ByteArrayInputStream(TEST_VALUE);
		lob = (String) ReflectionUtil.invokeMethod(type, "createLob",
				InputStream.class, long.class, SessionImplementor.class, bais, TEST_VALUE.length, null);
		assertEquals(TEXT_VALUE, lob);
	}

	@Test
	public void testStreamToLob() throws Exception {
		byte[] buff = TEST_VALUE;
		ByteArrayInputStream bais = new ByteArrayInputStream(buff);
		assertEquals(TEXT_VALUE, streamToLob(bais, null));

		// test < buffer size
		buff = new byte[getStreamBuffSize() >> 1];
		RANDOM.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		assertEquals(new String(buff, UTF8), streamToLob(bais, null));

		// test file buffering
		buff = new byte[getMaxInMemoryBuffSize() << 1];
		RANDOM.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		assertEquals(new String(buff, UTF8), streamToLob(bais, null));
	}

	@Test
	public void testSetStream() throws Exception {
		byte[] buff = TEST_VALUE;
		ByteArrayInputStream bais = new ByteArrayInputStream(buff);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		ps.setBytes(1, buff);
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		setStream(ps, 1, bais);
		EasyMock.verify(ps);

		EasyMock.resetToStrict(ps);

		// test < buffer size
		buff = new byte[getStreamBuffSize() >> 1];
		RANDOM.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		ps.setBytes(1, buff);
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		setStream(ps, 1, bais);
		EasyMock.verify(ps);

		EasyMock.resetToStrict(ps);

		// test file buffering
		buff = new byte[getMaxInMemoryBuffSize() << 1];
		RANDOM.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		final Capture<BufferedInputStream> capture = EasyMock.newCapture();
		ps.setBinaryStream(EasyMock.eq(1), EasyMock.capture(capture), EasyMock.eq((long) buff.length));
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		setStream(ps, 1, bais);
		EasyMock.verify(ps);
		// verify data is same
		final InputStream is = capture.getValue();
		assertArrayEquals(buff, StreamUtil.streamToBytes(is));
	}

	@Test
	public void testGetSet() throws Exception {
		final String[] columnNames = {"column1"};

		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		final Capture<byte[]> encBytesCapt = EasyMock.newCapture();
		ps.setBytes(EasyMock.eq(1), EasyMock.capture(encBytesCapt));
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		type.nullSafeSet(ps, TEXT_VALUE, 1, null);
		EasyMock.verify(ps);
		final byte[] enc = encBytesCapt.getValue();

		EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(enc));
		EasyMock.expect(rs.wasNull()).andReturn(false);
		EasyMock.replay(rs);
		final String dec = (String) type.nullSafeGet(rs, columnNames, null, null);
		EasyMock.verify(rs);

		assertEquals(TEXT_VALUE, dec);
	}


	private class TextEncryptThread extends EncryptThread {
		private final String[] columnNames = {"column1"};

		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		final ResultSet rs = EasyMock.strictMock(ResultSet.class);

		@Override
		protected void doIteration() throws Throwable {
			final Capture<byte[]> encBytesCapt = EasyMock.newCapture();
			ps.setBytes(EasyMock.eq(1), EasyMock.capture(encBytesCapt));
			EasyMock.expectLastCall();
			EasyMock.replay(ps);
			type.nullSafeSet(ps, TEXT_VALUE, 1, null);
			EasyMock.verify(ps);
			final byte[] enc = encBytesCapt.getValue();

			EasyMock.expect(rs.getBinaryStream(columnNames[0])).andReturn(new ByteArrayInputStream(enc));
			EasyMock.expect(rs.wasNull()).andReturn(false);
			EasyMock.replay(rs);
			final String dec = (String) type.nullSafeGet(rs, columnNames, null, null);
			EasyMock.verify(rs);
			assertEquals(TEXT_VALUE, dec);

			EasyMock.resetToStrict(ps, rs);
		}

	}

}
