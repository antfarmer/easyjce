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
import static org.junit.Assert.assertSame;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.antfarmer.common.util.ReflectionUtil;
import org.antfarmer.ejce.util.StreamUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public abstract class AbstractEncryptedLobTypeTest<T> extends AbstractEncryptedTypeTest<T> {

	public AbstractEncryptedLobTypeTest() {
		this(null, null);
	}

	public AbstractEncryptedLobTypeTest(final Charset encryptorCharset) {
		this(encryptorCharset, null);
	}

	public AbstractEncryptedLobTypeTest(final Charset encryptorCharset, final Properties encryptorProps) {
		super(encryptorCharset, encryptorProps == null ? new Properties() : encryptorProps);
	}

	protected InputStream encryptStream(final InputStream is) throws GeneralSecurityException, IOException {
		try {
			return ReflectionUtil.invokeMethod(type, "encryptStream", InputStream.class, is);
		}
		catch (final Exception e) {
			throw new GeneralSecurityException(e);
		}
	}

	protected InputStream decryptStream(final InputStream is) throws GeneralSecurityException, IOException {
		try {
			return ReflectionUtil.invokeMethod(type, "decryptStream", InputStream.class, is);
		}
		catch (final Exception e) {
			throw new GeneralSecurityException(e);
		}
	}

	@Override
	@Test
	public void test() throws Exception {
		final byte[] testValue = (byte[]) getTestValue();

		final InputStream enc = encryptStream(new ByteArrayInputStream(testValue));
		final InputStream dec = decryptStream(enc);
		assertArrayEquals(testValue, StreamUtil.streamToBytes(dec));

		assertSame(javaType, type.returnedClass());
	}

}
