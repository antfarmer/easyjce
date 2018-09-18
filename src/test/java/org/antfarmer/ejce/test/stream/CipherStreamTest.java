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
package org.antfarmer.ejce.test.stream;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.antfarmer.common.util.IoUtil;
import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.parameter.AlgorithmParameters;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.stream.EncryptInputStream;
import org.antfarmer.ejce.test.AbstractTest;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class CipherStreamTest extends AbstractTest {

	private static final String TEXT = "TEST";

	@Test
	public void testEnc() throws GeneralSecurityException, IOException {
		final AesParameters params = new AesParameters().setBlockMode(AesParameters.BLOCK_MODE_ECB);
		final ByteArrayInputStream bais = new ByteArrayInputStream(TEXT.getBytes(UTF8));
		final EncryptInputStream cs = createCipherStream(bais, params);
		final byte[] streamBytes = IoUtil.readBytes(cs);

		final Cipher cipher = Cipher.getInstance(params.getTransformation());
		cipher.init(Cipher.ENCRYPT_MODE, params.getKey());
		final byte[] cipherBytes = cipher.doFinal(TEXT.getBytes(UTF8));

		assertArrayEquals(streamBytes, cipherBytes);
	}

	@Test
	public void testSmallRead() throws GeneralSecurityException, IOException {
		final AesParameters params = new AesParameters().setSaltGenerator(new SaltGenerator() {
			@Override
			public void generateSalt(final byte[] saltData) {
				Arrays.fill(saltData, (byte)5);
			}
		});
		final int size = params.getParameterSpecSize();
		final byte[] buff = new byte[size >> 1];
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final ByteArrayInputStream bais = new ByteArrayInputStream(TEXT.getBytes(UTF8));
		final EncryptInputStream cs = createCipherStream(bais, params);

		int read;
		while ((read = cs.read(buff)) >= 0) {
			baos.write(buff, 0, read);
		}

		final Encryptor enc = new Encryptor().setAlgorithmParameters(params);
		enc.initialize();

		final byte[] streamResult = baos.toByteArray();
		final byte[] encResult = enc.encrypt(TEXT.getBytes(UTF8));

//		System.out.println(Arrays.toString(Arrays.copyOfRange(streamResult, 0, size)));
//		System.out.println(Arrays.toString(Arrays.copyOfRange(encResult, encResult.length - size, encResult.length)));
		assertArrayEquals(Arrays.copyOfRange(encResult, encResult.length - size, encResult.length), Arrays.copyOfRange(streamResult, 0, size));

//		System.out.println(Arrays.toString(Arrays.copyOfRange(streamResult, size, streamResult.length)));
//		System.out.println(Arrays.toString(Arrays.copyOfRange(encResult, 0, encResult.length - size)));
		assertArrayEquals(Arrays.copyOfRange(encResult, 0, encResult.length - size), Arrays.copyOfRange(streamResult, size, streamResult.length));
	}

	@Test
	public void testReset() throws GeneralSecurityException, IOException {
		final AesParameters params = new AesParameters();
		final int size = params.getParameterSpecSize();
		final byte[] buff1 = new byte[size];
		final byte[] buff2 = new byte[size];
		final ByteArrayInputStream bais = new ByteArrayInputStream(TEXT.getBytes(UTF8));
		final EncryptInputStream cs = createCipherStream(bais, params);
		cs.read(buff1);
		cs.reset();
		cs.read(buff2);
		assertArrayEquals(buff1, buff2);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testReadByte() throws GeneralSecurityException, IOException {
		final ByteArrayInputStream bais = new ByteArrayInputStream(TEXT.getBytes(UTF8));
		final EncryptInputStream cs = createCipherStream(bais, new AesParameters());
		cs.read();
	}

	private EncryptInputStream createCipherStream(final InputStream in, final AlgorithmParameters<?> parameters) throws GeneralSecurityException {
		final Cipher cipher = Cipher.getInstance(parameters.getTransformation());
		final byte[] specData = parameters.generateParameterSpecData();
		cipher.init(Cipher.ENCRYPT_MODE, parameters.getEncryptionKey(), specData == null ? null : parameters.createParameterSpec(specData));
		return new EncryptInputStream(in, cipher);
	}
}
