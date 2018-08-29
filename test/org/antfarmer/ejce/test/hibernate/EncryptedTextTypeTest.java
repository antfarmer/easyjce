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
import java.sql.SQLException;
import java.util.Properties;
import java.util.Random;

import org.antfarmer.ejce.hibernate.EncryptedTextType;
import org.antfarmer.ejce.test.hibernate.util.TypeUtil;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.antfarmer.ejce.util.StreamUtil;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedTextTypeTest extends EncryptedTextType {

	private static final Charset CHARSET = Charset.forName("UTF-8");
	private static String TEST_VALUE;
	private static final Random random = new Random();

	// TODO test functionally

	static {
		final byte[] content = new byte[10000];
		random.nextBytes(content);
		TEST_VALUE = new String(content, CHARSET);
	}

	/**
	 * @throws GeneralSecurityException
	 *
	 */
	@Before
	public void init() throws GeneralSecurityException {
		final Properties props = new Properties();
		props.put(ConfigurerUtil.KEY_COMPRESS_LOB, true);
		setParameterValues(TypeUtil.prepareTestEncryptorParameters(CHARSET, props));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void test() throws GeneralSecurityException, IOException {

		final InputStream enc = encryptStream(new ByteArrayInputStream(TEST_VALUE.getBytes(CHARSET)));
		final InputStream dec = decryptStream(enc);
		assertEquals(TEST_VALUE, new String(StreamUtil.streamToBytes(dec), CHARSET));
	}

	/**
	 *
	 */
	@Test
	public void testUnicode() throws GeneralSecurityException, IOException {
		final String o = "\u0627\u0645\u064a\u0631";

		// can run with '-Dfile.encoding=ISO-8859-1'
		System.out.println(Charset.defaultCharset());
		System.out.println(o);

		final InputStream enc = encryptStream(new ByteArrayInputStream(o.getBytes(CHARSET)));
		final InputStream dec = decryptStream(enc);
		final String decString = new String(StreamUtil.streamToBytes(dec), CHARSET);
		System.out.println(decString);
		assertEquals(o, decString);
	}

	/**
	 * @throws IOException
	 */
	@Test
	public void testLobToStream() throws IOException, SQLException {
		final InputStream is = lobToStream(TEST_VALUE);
		assertEquals(TEST_VALUE, new String(StreamUtil.streamToBytes(is), CHARSET));
	}

	/**
	 * @throws IOException
	 */
	@Test
	public void testCreateLob() throws IOException {
		String lob = (String) createLob(TEST_VALUE.getBytes(CHARSET), null);
		assertEquals(TEST_VALUE, lob);

		final byte[] buff = TEST_VALUE.getBytes(CHARSET);
		final ByteArrayInputStream bais = new ByteArrayInputStream(buff);
		lob = (String) createLob(bais, buff.length, null);
		assertEquals(TEST_VALUE, lob);
	}

	/**
	 * @throws IOException
	 */
	@Test
	public void testStreamToLob() throws IOException, SQLException {
		byte[] buff = TEST_VALUE.getBytes(CHARSET);
		ByteArrayInputStream bais = new ByteArrayInputStream(buff);
		assertEquals(TEST_VALUE, streamToLob(bais, null));

		// test < buffer size
		buff = new byte[getStreamBuffSize() >> 1];
		random.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		assertEquals(new String(buff, CHARSET), streamToLob(bais, null));

		// test file buffering
		buff = new byte[getMaxInMemoryBuffSize() << 1];
		random.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		assertEquals(new String(buff, CHARSET), streamToLob(bais, null));
	}

	/**
	 * @throws IOException
	 * @throws SQLException
	 */
	@Test
	public void testSetStreamBuffered() throws IOException, SQLException {
		byte[] buff = TEST_VALUE.getBytes(CHARSET);
		ByteArrayInputStream bais = new ByteArrayInputStream(buff);
		final PreparedStatement ps = EasyMock.strictMock(PreparedStatement.class);
		ps.setBytes(1, buff);
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		setStreamBuffered(ps, 1, bais);
		EasyMock.verify(ps);

		EasyMock.resetToStrict(ps);

		// test < buffer size
		buff = new byte[getStreamBuffSize() >> 1];
		random.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		ps.setBytes(1, buff);
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		setStreamBuffered(ps, 1, bais);
		EasyMock.verify(ps);

		EasyMock.resetToStrict(ps);

		// test file buffering
		buff = new byte[getMaxInMemoryBuffSize() << 1];
		random.nextBytes(buff);
		bais = new ByteArrayInputStream(buff);
		final Capture<BufferedInputStream> capture = EasyMock.newCapture();
		ps.setBinaryStream(EasyMock.eq(1), EasyMock.capture(capture), EasyMock.eq(buff.length));
		EasyMock.expectLastCall();
		EasyMock.replay(ps);
		setStreamBuffered(ps, 1, bais);
		EasyMock.verify(ps);
		// verify data is same
		final InputStream is = capture.getValue();
		assertArrayEquals(buff, StreamUtil.streamToBytes(is));
	}

	/**
	 *
	 */
	@Test
	public void testThreadSafety() {
		final int num = 25;
		final EncryptThread[] threads = new EncryptThread[num];
		for (int i=0; i<num; i++) {
			threads[i] = new EncryptThread();
			threads[i].start();
		}
		for (int i=0; i<num; i++) {
			try {
				threads[i].join();
			}
			catch (final InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private class EncryptThread extends Thread {

		/**
		 * {@inheritDoc}
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<50; i++) {
					final InputStream enc = encryptStream(new ByteArrayInputStream(TEST_VALUE.getBytes(CHARSET)));
					assertEquals(TEST_VALUE, new String(StreamUtil.streamToBytes(decryptStream(enc)), CHARSET));
				}
			}
			catch (final Exception e) {
				e.printStackTrace();
			}
		}

	}

}
