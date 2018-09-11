/*
 * Copyright 2006 Ameer Antar.
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

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.antfarmer.ejce.util.ByteUtil;

/**
 * Extension of <code>CipherInputStream</code> that transmits the given cipher's initialization vector (if any) at the
 * beginning of the stream.
 * @author Ameer Antar
 */
public class EncryptInputStream extends CipherInputStream {

	private final byte[] iv;
	private byte[] remainder;

	/**
	 * Constructor.
	 * @param is the <code>InputStream</code> to be encrypted
	 * @param c the encryption <code>Cipher</code>
	 */
	public EncryptInputStream(final InputStream is, final Cipher c) {
		super(is, c);
		iv = c.getIV();
		if (iv != null) {
			remainder = ByteUtil.copy(iv);
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
		if (remainder == null) {
			return super.read(b, off, len);
		}

		final int rlen = remainder.length;
		if (rlen <= len) {
			System.arraycopy(remainder, 0, b, off, rlen);
			remainder = null;
			return rlen + super.read(b, off + rlen, len - rlen);
		}

		System.arraycopy(remainder, 0, b, off, len);
		remainder = ByteUtil.copy(remainder, len, rlen - len);
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
	public synchronized void reset() throws IOException {
		super.reset();
		remainder = ByteUtil.copy(iv);
	}

}
