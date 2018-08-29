/*
 * Copyright 2006-2007 the original author or authors.
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
package org.antfarmer.ejce.hibernate;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Properties;
import java.util.zip.GZIPInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.antfarmer.ejce.parameter.AlgorithmParameters;
import org.antfarmer.ejce.stream.EncryptInputStream;
import org.antfarmer.ejce.stream.GZIPCompressionStream;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SessionImplementor;

/**
 * Abstract extension of <code>AbstractHibernateType</code> for LOB types that encrypts as well as compresses
 * arbitrarily large binary data.
 * @see AbstractHibernateType
 * @author Ameer Antar
 */
public abstract class AbstractLobType extends AbstractHibernateType {

	private static final int[] sqlTypes = {Types.BLOB};
	private static final File TEMP_DIR = new File(System.getProperty("java.io.tmpdir"));
	private static final String TEMP_FILE_PREFIX = "ejce_";

	private boolean useCompression;
	private int streamBuffSize = 4 * 1024;
	private int maxInMemoryBuffSize = 512 * 1024;
	private Method jdbc4SetBinaryStreamMethod;
	private AlgorithmParameters<?> parameters;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int[] sqlTypes() {
		return sqlTypes;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void configure(final Properties parameters) {
		String value;

		// check if compression is enabled
		value = parameters.getProperty(ConfigurerUtil.KEY_COMPRESS_LOB);
		if (value != null) {
			useCompression = value.trim().toLowerCase().equals("true");
		}

		Integer intVal;

		// set streaming buffer size
		value = parameters.getProperty(ConfigurerUtil.KEY_STREAM_BUFF_SIZE);
		intVal = ConfigurerUtil.parseInt(value);
		if (intVal != null && intVal > 1) {
			streamBuffSize = intVal;
		}

		// set max in memory buffer size
		value = parameters.getProperty(ConfigurerUtil.KEY_MAX_IN_MEM_BUFF_SIZE);
		intVal = ConfigurerUtil.parseInt(value);
		if (intVal != null && intVal > 1) {
			maxInMemoryBuffSize = intVal;
		}

		// check if JDBC4 is available
		jdbc4SetBinaryStreamMethod = getJdbc4SetBinaryStreamMethod();

		this.parameters = ConfigurerUtil.loadAlgorithmParameters(parameters, null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void nullSafeSet(final PreparedStatement st, final Object value, final int index, final SessionImplementor session)
			throws HibernateException, SQLException {
		if (value == null) {
			st.setNull(index, sqlTypes()[0]);
		}
		else {
			try {
				setStream(st, index, encryptStream(lobToStream(value)));
			}
			catch (final GeneralSecurityException e) {
				throw new HibernateException("Error encrypting object.", e);
			}
			catch (final IOException e) {
				throw new HibernateException("Error encrypting object.", e);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Object nullSafeGet(final ResultSet rs, final String[] names, final SessionImplementor session, final Object owner)
			throws HibernateException, SQLException {
		final InputStream is = rs.getBinaryStream(names[0]);
		try {
			if (rs.wasNull()) {
				return null;
			}
			return streamToLob(decryptStream(is), session);
		}
		catch (final GeneralSecurityException e) {
			throw new HibernateException("Error decrypting object.", e);
		}
		catch (final IOException e) {
			throw new HibernateException("Error decrypting object.", e);
		}
	}

	/**
	 * Encrypts the given <tt>InputStream</tt>.
	 * @param is the InputStream
	 * @return an encrypted InputStream
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	protected InputStream encryptStream(final InputStream is) throws GeneralSecurityException, IOException {
		final Cipher cipher = ConfigurerUtil.getCipherInstance(parameters);
		final byte[] paramData = parameters.generateParameterSpecData();
		final AlgorithmParameterSpec paramSpec = parameters.createParameterSpec(paramData);
		cipher.init(Cipher.ENCRYPT_MODE, parameters.getEncryptionKey(), paramSpec);
		return useCompression ? new EncryptInputStream(new GZIPCompressionStream(is), cipher)
			: new EncryptInputStream(is, cipher);
	}

	/**
	 * Decrypts the given <tt>InputStream</tt>.
	 * @param is the InputStream
	 * @return a decrypted InputStream
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	protected InputStream decryptStream(final InputStream is) throws GeneralSecurityException, IOException {
		final Cipher cipher = ConfigurerUtil.getCipherInstance(parameters);
		final int paramSize = parameters.getParameterSpecSize();
		AlgorithmParameterSpec algorithmSpec = null;
		if (paramSize > 0) {
			final byte[] buff = new byte[paramSize];
			if (is.read(buff) < paramSize) {
				throw new GeneralSecurityException("Error loading parameter spec data.");
			}
			algorithmSpec = parameters.getParameterSpec(buff);
		}
		cipher.init(Cipher.DECRYPT_MODE, parameters.getEncryptionKey(), algorithmSpec);
		return useCompression ? new GZIPInputStream(new CipherInputStream(is, cipher)) : new CipherInputStream(is, cipher);
	}

	/**
	 * Sets the given <tt>InputStream</tt> on the <tt>PreparedStatement</tt>.
	 * @param st the PreparedStatement
	 * @param index the parameter index
	 * @param is the InputStream
	 * @throws IOException
	 * @throws SQLException
	 */
	protected void setStream(final PreparedStatement st, final int index, final InputStream is) throws IOException, SQLException {
		if (setStreamJdbc4(st, index, is)) {
			return;
		}
		setStreamBuffered(st, index, is);
	}

	/**
	 * Sets the <tt>InputStream</tt> on the given <tt>PreparedStatement</tt>. If the given <tt>InputStream</tt> contains
	 * less data than the <tt>maxInMemoryBuffSize</tt> setting, the data will be set on the <tt>PreparedStatement</tt>
	 * using an in-memory byte array. Otherwise, the stream will be set via a temporary file to determine its true
	 * length and limit memory usage.
	 * @param st the PreparedStatement
	 * @param index the parameter index
	 * @param is the InputStream
	 * @throws IOException
	 * @throws SQLException
	 */
	protected void setStreamBuffered(final PreparedStatement st, final int index, final InputStream is) throws IOException, SQLException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream(streamBuffSize);
		try {
			int read;
			int totalRead = 0;
			final byte[] buff = new byte[streamBuffSize];
			while ((read = is.read(buff)) > -1) {
				baos.write(buff, 0, read);
				totalRead += read;
				if (totalRead >= maxInMemoryBuffSize) {
					break;
				}
			}
			if (totalRead < maxInMemoryBuffSize) {
				st.setBytes(index, baos.toByteArray());
			}
			else {
				File file = createTempFile();
				final FileOutputStream fos = new FileOutputStream(file);
				try {
					fos.write(baos.toByteArray());
					while ((read = is.read(buff)) > -1) {
						fos.write(buff, 0, read);
					}
				}
				finally {
					fos.close();
				}
				file = new File(file.getAbsolutePath());
				st.setBinaryStream(index, new BufferedInputStream(new FileInputStream(file)), (int) file.length());
			}
		}
		finally {
			is.close();
		}
	}

	protected Object streamToLob(final InputStream is, final SessionImplementor session) throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream(streamBuffSize);
		try {
			int read;
			int totalRead = 0;
			final byte[] buff = new byte[streamBuffSize];
			while ((read = is.read(buff)) > -1) {
				baos.write(buff, 0, read);
				totalRead += read;
				if (totalRead >= maxInMemoryBuffSize) {
					break;
				}
			}
			if (totalRead < maxInMemoryBuffSize) {
				return createLob(baos.toByteArray(), session);
			}
			else {
				File file = createTempFile();
				final FileOutputStream fos = new FileOutputStream(file);
				try {
					fos.write(baos.toByteArray());
					while ((read = is.read(buff)) > -1) {
						fos.write(buff, 0, read);
					}
				}
				finally {
					fos.close();
				}
				file = new File(file.getAbsolutePath());
				return createLob(new BufferedInputStream(new FileInputStream(file)), file.length(), session);
			}
		}
		finally {
			is.close();
		}
	}

	/**
	 * Returns a newly created temp file. The file will be deleted on normal termination of the VM.
	 * @return a newly created temp file
	 * @throws IOException
	 */
	protected File createTempFile() throws IOException {
		File file;
		while (!(file = new File(TEMP_DIR, generateTempFileName())).createNewFile()) {
			// loop
		}
		file.deleteOnExit();
		return file;
	}

	/**
	 * Returns a temp file name based on the current time and a random number.
	 * @return a temp file name based on the current time and a random number
	 */
	protected String generateTempFileName() {
		return TEMP_FILE_PREFIX + System.currentTimeMillis() + "-" + random.nextInt(100);
	}

	/**
	 * Sets the given <tt>InputStream</tt> on the JDBC4 <tt>PreparedStatement</tt> using reflective invocation.
	 * @param st the PreparedStatement
	 * @param index the parameter index
	 * @param is the InputStream
	 * @return true if the stream was successfully set; false otherwise
	 */
	protected boolean setStreamJdbc4(final PreparedStatement st, final int index, final InputStream is) {
		if (jdbc4SetBinaryStreamMethod == null) {
			return false;
		}

		try {
			jdbc4SetBinaryStreamMethod.invoke(st, index, is);
			return true;
		}
		catch (final IllegalAccessException e) {
			jdbc4SetBinaryStreamMethod = null;
			e.printStackTrace();
			return false;
		}
		catch (final InvocationTargetException e) {
			jdbc4SetBinaryStreamMethod = null;
			e.printStackTrace();
			return false;
		}
		catch (final IllegalArgumentException e) {
			jdbc4SetBinaryStreamMethod = null;
			e.printStackTrace();
			return false;
		}
		catch (final RuntimeException e) {
			jdbc4SetBinaryStreamMethod = null;
			e.printStackTrace();
			return false;
		}
	}

	private Method getJdbc4SetBinaryStreamMethod() {
		try {
			return PreparedStatement.class.getMethod("setBinaryStream", int.class, InputStream.class);
		}
		catch (final SecurityException e) {
			return null;
		}
		catch (final RuntimeException e) {
			return null;
		}
		catch (final NoSuchMethodException e) {
			return null;
		}
	}

	/**
	 * Converts the LOB value to an <tt>InputStream</tt>.
	 * @param value the LOB value
	 * @return the InputStream
	 * @throws SQLException an error converting the value to an InputStream
	 */
	protected abstract InputStream lobToStream(Object value) throws SQLException;

	/**
	 * Converts the <tt>InputStream</tt> to a LOB.
	 * @param is the InputStream
	 * @param length the stream length
	 * @param session the {@link SessionImplementor}
	 * @return the LOB
	 * @throws IOException an error converting the stream to a LOB
	 */
	protected abstract Object createLob(InputStream is, long length, SessionImplementor session) throws IOException;

	/**
	 * Converts the <tt>InputStream</tt> to a LOB.
	 * @param bytes the bytes
	 * @param session the {@link SessionImplementor}
	 * @return the LOB
	 * @throws IOException an error converting the stream to a LOB
	 */
	protected abstract Object createLob(byte[] bytes, SessionImplementor session) throws IOException;

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Object decrypt(final String value) throws GeneralSecurityException {
		// not used
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String encrypt(final Object value) throws GeneralSecurityException {
		// not used
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public abstract Class<?> returnedClass();

}
