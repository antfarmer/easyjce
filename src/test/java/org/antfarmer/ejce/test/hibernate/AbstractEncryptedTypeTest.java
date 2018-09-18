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

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.antfarmer.common.util.ReflectionUtil;
import org.antfarmer.ejce.hibernate.AbstractHibernateType;
import org.antfarmer.ejce.test.AbstractTest;
import org.antfarmer.ejce.test.hibernate.util.TypeUtil;
import org.antfarmer.ejce.test.utils.TestUtil;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public abstract class AbstractEncryptedTypeTest<T> extends AbstractTest {

	private static final int THREAD_COUNT = 25;

	private static final int THREAD_ITERATIONS = 50;

	protected final AbstractHibernateType type = createHibernateType();

	protected final Class<T> javaType = TestUtil.getGenericType(getClass(), Object.class);

	private Charset encryptorCharset;
	private Properties encryptorProps;

	public AbstractEncryptedTypeTest() {
		// nothing
	}

	public AbstractEncryptedTypeTest(final Charset encryptorCharset) {
		this.encryptorCharset = encryptorCharset;
	}

	public AbstractEncryptedTypeTest(final Charset encryptorCharset, final Properties encryptorProps) {
		this.encryptorCharset = encryptorCharset;
		this.encryptorProps = encryptorProps;
	}

	/**
	 * @return the value to be used for testing (should be cached)
	 */
	protected abstract Object getTestValue();

	/**
	 * @return a new instance of the {@link AbstractHibernateType} under test
	 */
	protected abstract AbstractHibernateType createHibernateType();

	@Before
	public void init() throws GeneralSecurityException {
		type.setParameterValues(
				encryptorProps == null
				? TypeUtil.prepareTestEncryptor(encryptorCharset)
				: TypeUtil.prepareTestEncryptorParameters(encryptorCharset, encryptorProps)
		);
	}

	protected Object decrypt(final String value) throws GeneralSecurityException {
		try {
			return ReflectionUtil.invokeMethod(type, "decrypt", String.class, value);
		}
		catch (final Exception e) {
			throw new GeneralSecurityException(e);
		}
	}

	protected String encrypt(final Object value) throws GeneralSecurityException {
		try {
			return ReflectionUtil.invokeMethod(type, "encrypt", Object.class, value);
		}
		catch (final Exception e) {
			throw new GeneralSecurityException(e);
		}
	}

	@Test
	public void test() throws Exception {
		final Object o = getTestValue();
		final String enc = encrypt(o);
		System.out.println(enc);
		final Object dec = decrypt(enc);
		System.out.println(dec);
		assertEquals(o, dec);

		assertSame(javaType, type.returnedClass());
	}

	@Test
	public void testThreadSafety() throws Throwable {
		final int num = THREAD_COUNT;
		final List<EncryptThread> threads = new ArrayList<EncryptThread>(num);
		EncryptThread thread;
		for (int i=0; i<num; i++) {
			thread = createEncryptThread();
			threads.add(thread);
			thread.start();
		}
		for (int i=0; i<num; i++) {
			thread = threads.get(i);
			thread.join();
			if (thread.exception != null) {
				throw thread.exception;
			}
		}
	}

	protected EncryptThread createEncryptThread() {
		return new EncryptThread();
	}

	protected class EncryptThread extends Thread {
		protected final Object testValue = getTestValue();
		protected Throwable exception;

		@Override
		public void run() {
			try {
				for (int i=0; i<THREAD_ITERATIONS; i++) {
					doIteration();
				}
			}
			catch (final Throwable e) {
				exception = e;
				e.printStackTrace();
			}
		}

		protected void doIteration() throws Throwable {
			final String enc = encrypt(testValue);
			assertEquals(testValue, decrypt(enc));
		}
	}

}
