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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.SQLException;
import java.util.Arrays;

import org.antfarmer.ejce.test.db.AbstractDbTest;

/**
 * @author Ameer Antar
 */
public abstract class AbstractLobDbTest extends AbstractDbTest {

	private static final int BUFF_SIZE = 4096;

	private static final String TMP_PATH = System.getProperty("java.io.tmpdir");

	/**
	 * Creates a file with random data.
	 * @param length the file length
	 * @return the file
	 * @throws IOException
	 */
	protected File createRandomDataFile(final int length) throws IOException {
		return createRandomDataFile(length, false);
	}

	/**
	 * Creates a file with random data, optionally only containing ASCII characters.
	 * @param length the file length
	 * @param createText indicates whether to only store random ASCII characters in the file
	 * @return the file
	 * @throws IOException
	 */
	protected File createRandomDataFile(final int length, final boolean createText) throws IOException {
		final File file = new File(TMP_PATH, "file.txt");
		file.deleteOnExit();
		byte[] buff = new byte[length < BUFF_SIZE ? length : BUFF_SIZE];
		int total = 0;
		final OutputStream os = new BufferedOutputStream(new FileOutputStream(file));
		try {
			while (total < length) {
				if (createText) {
					for (int j = 0; j < buff.length; j++) {
						buff[j] = (byte) (33 + RANDOM.nextInt(94));
					}
				}
				else {
					RANDOM.nextBytes(buff);
				}
				os.write(buff);
				total += buff.length;
				final int remaining = length - total;
				if (remaining > 0 && remaining < BUFF_SIZE) {
					buff = new byte[remaining];
				}
			}
		}
		finally {
			close(os);
		}
		return new File(file.getAbsolutePath());
	}

	/**
	 * Asserts whether the file and clob are equal or not.
	 * @param isEqual whether the assertion is to be equal or not
	 * @param file the file
	 * @param clob the clob
	 * @throws SQLException
	 * @throws IOException
	 */
	protected void assertData(final boolean isEqual, final File file, final Clob clob) throws SQLException, IOException {
		assertData(isEqual, file, new ClobBlob(clob));
	}

	/**
	 * Asserts whether the file and blob are equal or not.
	 * @param isEqual whether the assertion is to be equal or not
	 * @param file the file
	 * @param blob the blob
	 * @throws SQLException
	 * @throws IOException
	 */
	protected void assertData(final boolean isEqual, final File file, final Blob blob) throws SQLException, IOException {
		if (isEqual) {
			assertEquals(file.length(), blob.length());
		}
		else if (file.length() != blob.length()) {
			return;
		}

		final InputStream fis = new BufferedInputStream(new FileInputStream(file));
		try {
			final InputStream bis = new BufferedInputStream(blob.getBinaryStream());
			try {
				int fRead, bRead;
				final byte[] fBuff = new byte[BUFF_SIZE], bBuff = new byte[BUFF_SIZE];
				while ((bRead = bis.read(bBuff)) >= 0) {
					fRead = fis.read(fBuff);
					if (isEqual) {
						assertEquals(fRead, bRead);
						if (fRead == fBuff.length) {
							assertArrayEquals(fBuff, bBuff);
						}
						else {
							assertArrayEquals(Arrays.copyOfRange(fBuff, 0, fRead), Arrays.copyOfRange(bBuff, 0, bRead));
						}
					}
					else {
						if (fRead != bRead) {
							return;
						}
						if (fRead == fBuff.length) {
							if (!Arrays.equals(fBuff, bBuff)) {
								return;
							}
						}
						else {
							if (!Arrays.equals(Arrays.copyOfRange(fBuff, 0, fRead), Arrays.copyOfRange(bBuff, 0, bRead))) {
								return;
							}
						}
					}
				}
			}
			finally {
				close(bis);
			}
		}
		finally {
			close(fis);
		}

		if (!isEqual) {
			assertTrue("Values were the same", isEqual);
		}
	}

	/**
	 * Closes the given {@link Closeable}.
	 * @param closeable
	 */
	protected void close(final Closeable closeable) {
		if (closeable == null) return;
		try {
			closeable.close();
		}
		catch (final IOException e) {
			// ignore
		}
	}

	private static class ClobBlob implements Blob {

		private final Clob clob;

		public ClobBlob(final Clob clob) {
			this.clob = clob;
		}

		@Override
		public long length() throws SQLException {
			return clob.length();
		}

		@Override
		public byte[] getBytes(final long pos, final int length) throws SQLException {
			throw new UnsupportedOperationException("Operation not supported");
		}

		@Override
		public InputStream getBinaryStream() throws SQLException {
			return clob.getAsciiStream();
		}

		@Override
		public long position(final byte[] pattern, final long start) throws SQLException {
			throw new UnsupportedOperationException("Operation not supported");
		}

		@Override
		public long position(final Blob pattern, final long start) throws SQLException {
			throw new UnsupportedOperationException("Operation not supported");
		}

		@Override
		public int setBytes(final long pos, final byte[] bytes) throws SQLException {
			throw new UnsupportedOperationException("Operation not supported");
		}

		@Override
		public int setBytes(final long pos, final byte[] bytes, final int offset, final int len) throws SQLException {
			throw new UnsupportedOperationException("Operation not supported");
		}

		@Override
		public OutputStream setBinaryStream(final long pos) throws SQLException {
			return clob.setAsciiStream(pos);
		}

		@Override
		public void truncate(final long len) throws SQLException {
			clob.truncate(len);
		}

		@Override
		public void free() throws SQLException {
			clob.free();
		}

		@Override
		public InputStream getBinaryStream(final long pos, final long length) throws SQLException {
			throw new UnsupportedOperationException("Operation not supported");
		}

	}
}
