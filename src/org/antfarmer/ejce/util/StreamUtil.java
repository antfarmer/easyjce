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
package org.antfarmer.ejce.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Stream utility methods.
 * @author Ameer Antar
 */
public class StreamUtil {

	private static final int BUFF_SIZE = 4096;

	private StreamUtil() {
		// static methods only
	}

	/**
	 * Returns a byte array containing the data from the given InputStream.
	 * @param is the InputStream
	 * @return a byte array containing the data from the given InputStream
	 * @throws IOException an IOException occurred
	 */
	public static byte[] streamToBytes(final InputStream is) throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream(BUFF_SIZE);
		copyStream(is, baos);
		return baos.toByteArray();
	}

	/**
	 * Copies data from the given InputStream to the given OutputStream.
	 * @param is the InputStream
	 * @param os the OutputStream
	 * @throws IOException an IOException occurred
	 */
	public static void copyStream(final InputStream is, final OutputStream os) throws IOException {
		copyStream(is, os, BUFF_SIZE);
	}

	/**
	 * Copies data from the given InputStream to the given OutputStream.
	 * @param is the InputStream
	 * @param os the OutputStream
	 * @param bufferSize the buffer size in bytes
	 * @throws IOException an IOException occurred
	 */
	public static void copyStream(final InputStream is, final OutputStream os, final int bufferSize) throws IOException {
		final byte[] buff = new byte[bufferSize];
		int read;
		try {
			while ((read = is.read(buff)) > -1) {
				os.write(buff, 0, read);
			}
		}
		finally {
			is.close();
			os.close();
		}
	}

}
