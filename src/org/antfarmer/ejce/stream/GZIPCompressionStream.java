/*
 * Copyright 2006-2009 the original author or authors.
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
package org.antfarmer.ejce.stream;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPOutputStream;

/**
 * An <code>InputStream</code> wrapper that compresses the data within the given <code>InputStream</code>.
 * @author Ameer Antar
 */
public class GZIPCompressionStream extends FilterInputStream {

	private final ByteArrayOutputStream baos = new ByteArrayOutputStream(4096);
	private final GZIPOutputStream gos;
	private final ThreadLocal<byte[]> accumulator = new ThreadLocal<byte[]>();

	/**
	 * Constructor.
	 * @param in the <code>InputStream</code> to be compressed
	 * @throws IOException
	 */
	public GZIPCompressionStream(final InputStream in) throws IOException {
		super(in);
		gos = new GZIPOutputStream(baos);
		// write header
		if (baos.size() > 0) {
			accumulator.set(baos.toByteArray());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int read() throws IOException {
		throw new UnsupportedOperationException("read() method not supported");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int read(final byte[] b, final int off, final int len) throws IOException {
		final byte[] accumulated = accumulator.get();
		if (accumulated != null) {
			return processRead(b, off, len, accumulated);
		}

		final int read = super.read(b, off, len);
		if (read == -1) {
			baos.reset();
			gos.close();

			final byte[] compressed = baos.toByteArray();
			return compressed.length < 1 ? read : processRead(b, off, len, compressed);
		}
		else if (read == 0) {
			return read;
		}
		baos.reset();
		gos.write(b, off, read);

		final byte[] compressed = baos.toByteArray();
		return processRead(b, off, len, compressed);
	}

	private int processRead(final byte[] b, final int off, final int len, final byte[] processed) {
		final int clen = processed.length;
		if (clen <= len) {
			System.arraycopy(processed, 0, b, off, clen);
			accumulator.set(null);
			return clen;
		}

		System.arraycopy(processed, 0, b, off, len);
		final byte[] remainder = new byte[clen - len];
		System.arraycopy(processed, len, remainder, 0, remainder.length);
		accumulator.set(remainder);
		return len;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int read(final byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void close() throws IOException {
		accumulator.set(null);
		super.close();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized void reset() throws IOException {
		accumulator.set(null);
		super.reset();
	}

}
