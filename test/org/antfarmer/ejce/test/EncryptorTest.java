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
package org.antfarmer.ejce.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.TimeZone;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.ValueEncryptorInterface;
import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.exception.MacDisagreementException;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.parameter.BlowfishParameters;
import org.antfarmer.ejce.parameter.DesEdeParameters;
import org.antfarmer.ejce.parameter.DesParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.parameter.Rc2Parameters;
import org.antfarmer.ejce.parameter.Rc4Parameters;
import org.antfarmer.ejce.parameter.RsaParameters;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;
import org.antfarmer.ejce.util.ByteUtil;
import org.antfarmer.ejce.util.CryptoUtil;
import org.junit.Ignore;
import org.junit.Test;


/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptorTest {
	private static ValueEncryptorInterface<Encryptor> encryptor;
	private static final String PBE_KEY = "password";
	private static final String TEST_TEXT = "abcdefghijklmnopqrstuvwxyz";

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testStream() throws GeneralSecurityException {
		final AesParameters parameters = new AesParameters()
				.setKeySize(AesParameters.KEY_SIZE_128)
//				.setBlockMode(AesParameters.BLOCK_MODE_ECB)
//				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
//				.setMacKeySize(AesParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor().setAlgorithmParameters(parameters);
		encryptor.initialize();

		final byte[] enc = encryptor.encrypt("a".getBytes());
		System.out.println(enc.length);
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void threadSafetyTest() throws GeneralSecurityException {

		final AesParameters parameters = new AesParameters(Base64Encoder.getInstance())
				.setKeySize(AesParameters.KEY_SIZE_128)
				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(AesParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

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

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final long l = 99;
		final String enc = encryptor.encryptAndEncode(ByteUtil.toBytes(l));
		assertEquals(l, ByteUtil.toLong(encryptor.decryptAndDecode(enc)));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testBooleanEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final boolean o = true;
		final String enc = encryptor.encryptBoolean(o);
		assertEquals(o, encryptor.decryptBoolean(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testCharacterEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Character o = 'z';
		final String enc = encryptor.encryptCharacter(o);
		assertEquals(o, encryptor.decryptCharacter(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testDoubleEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Double o = 9.99999999999999;
		final String enc = encryptor.encryptDouble(o);
		assertEquals(o, encryptor.decryptDouble(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testFloatEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Float o = 9.99999999999999F;
		final String enc = encryptor.encryptFloat(o);
		assertEquals(o, encryptor.decryptFloat(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testIntegerEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Integer o = 66666666;
		final String enc = encryptor.encryptInteger(o);
		assertEquals(o, encryptor.decryptInteger(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testLongEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Long o = 6666666666666666666L;
		final String enc = encryptor.encryptLong(o);
		assertEquals(o, encryptor.decryptLong(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	@Test
	public void testObjectEncryption() throws GeneralSecurityException, IOException, ClassNotFoundException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Object o = TimeZone.getDefault();
		final String enc = encryptor.encryptObject(o);
		assertEquals(o, encryptor.decryptObject(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testShortEncryption() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setKey(PBE_KEY)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Short o = 5555;
		final String enc = encryptor.encryptShort(o);
		assertEquals(o, encryptor.decryptShort(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final long l = 99;
		final String enc = encryptor.encryptAndEncode(ByteUtil.toBytes(l), key);
		assertEquals(l, ByteUtil.toLong(encryptor.decryptAndDecode(enc, key)));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test(expected = GeneralSecurityException.class)
	public void testEncryptionWithSpecKeyNotUsingInstanceKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Long l = 99L;
		final String enc = encryptor.encryptAndEncode(ByteUtil.toBytes(l), key);
		assertFalse(l.equals(ByteUtil.toLong(encryptor.decryptAndDecode(enc))));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testBooleanEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final boolean o = true;
		final String enc = encryptor.encryptBoolean(o, key);
		assertEquals(o, encryptor.decryptBoolean(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testCharacterEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Character o = 'z';
		final String enc = encryptor.encryptCharacter(o, key);
		assertEquals(o, encryptor.decryptCharacter(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testDoubleEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Double o = 9.99999999999999;
		final String enc = encryptor.encryptDouble(o, key);
		assertEquals(o, encryptor.decryptDouble(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testFloatEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Float o = 9.99999999999999F;
		final String enc = encryptor.encryptFloat(o, key);
		assertEquals(o, encryptor.decryptFloat(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testIntegerEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Integer o = 66666666;
		final String enc = encryptor.encryptInteger(o, key);
		assertEquals(o, encryptor.decryptInteger(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testLongEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Long o = 6666666666666666666L;
		final String enc = encryptor.encryptLong(o, key);
		assertEquals(o, encryptor.decryptLong(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	@Test
	public void testObjectEncryptionWithSpecKey() throws GeneralSecurityException, IOException, ClassNotFoundException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Object o = TimeZone.getDefault();
		final String enc = encryptor.encryptObject(o, key);
		assertEquals(o, encryptor.decryptObject(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testShortEncryptionWithSpecKey() throws GeneralSecurityException {

		final PbeParameters parameters = new PbeParameters(Base64Encoder.getInstance())
				.setAlgorithm(PbeParameters.ALGORITHM_PBE_MD5_DES)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, parameters.getAlgorithm());
		final Short o = 5555;
		final String enc = encryptor.encryptShort(o, key);
		assertEquals(o, encryptor.decryptShort(enc, key));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test(expected=MacDisagreementException.class)
	public void testMacDisagreement() throws GeneralSecurityException {

		final DesParameters parameters = new DesParameters(Base64Encoder.getInstance())
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_160)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final byte[] bytes = TEST_TEXT.getBytes();
		final byte[] enc = encryptor.encrypt(bytes);
		enc[enc.length - 1] += 1;
		encryptor.decrypt(enc);
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testAes() throws GeneralSecurityException {
		final AesParameters parameters = new AesParameters()
				.setKeySize(AesParameters.KEY_SIZE_128)
				.setBlockMode(AesParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(AesParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testAesEcb() throws GeneralSecurityException {
		final AesParameters parameters = new AesParameters()
				.setKeySize(AesParameters.KEY_SIZE_128)
				.setBlockMode(AesParameters.BLOCK_MODE_ECB)
				.setBlockSize(32)
				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(AesParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testAesWithCustomSalts() throws GeneralSecurityException {
		final byte[] salt = new byte[AesParameters.DEFAULT_BLOCK_SIZE];
		Arrays.fill(salt, (byte)99);
		final AesParameters parameters = new AesParameters()
				.setKeySize(AesParameters.KEY_SIZE_128)
				.setBlockMode(AesParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(AesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(AesParameters.MAC_KEY_SIZE_128)
				.setSaltGenerator(new SaltGenerator() {
					public void generateSalt(final byte[] saltData) {
						System.arraycopy(salt, 0, saltData, 0, salt.length);
					}
				})
				.setSaltMatcher(new SaltMatcher() {
					public void verifySaltMatch(final byte[] cipherSalt) throws GeneralSecurityException {
						if (!Arrays.equals(cipherSalt, salt)) {
							throw new GeneralSecurityException("Salt did not match");
						}
					}
				})
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testBlowfish() throws GeneralSecurityException {
		final BlowfishParameters parameters = new BlowfishParameters()
				.setKeySize(BlowfishParameters.KEY_SIZE_128)
				.setBlockMode(BlowfishParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(BlowfishParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testDesEde() throws GeneralSecurityException {
		final DesEdeParameters parameters = new DesEdeParameters()
				.setKeySize(DesEdeParameters.KEY_SIZE_DES_EDE_112)
				.setBlockMode(DesEdeParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(DesEdeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(DesEdeParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testDesEdeEcb() throws GeneralSecurityException {
		final DesEdeParameters parameters = new DesEdeParameters()
				.setKeySize(DesEdeParameters.KEY_SIZE_DES_EDE_112)
				.setBlockMode(DesEdeParameters.BLOCK_MODE_ECB)
				.setBlockSize(32)
				.setMacAlgorithm(DesEdeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(DesEdeParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testDes() throws GeneralSecurityException {
		final DesParameters parameters = new DesParameters()
				.setKeySize(DesParameters.KEY_SIZE_DES_56)
				.setBlockMode(DesParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(DesParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(DesParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testPbe() throws GeneralSecurityException {
		final PbeParameters parameters = new PbeParameters()
				.setKey(PBE_KEY)
				.setBlockMode(PbeParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testPbeWithGeneratedPassword() throws GeneralSecurityException {
		final PbeParameters parameters = new PbeParameters()
				.setBlockMode(PbeParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test(expected=InvalidAlgorithmParameterException.class)
	public void testPbeNoSalt() throws GeneralSecurityException {
		final PbeParameters parameters = new PbeParameters()
				.setKey(PBE_KEY)
				.setSaltSize(0)
				.setBlockMode(PbeParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(PbeParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(PbeParameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Ignore	// this only works with unlimited strength encryption policy files
	public void testRc2() throws GeneralSecurityException {
		final Rc2Parameters parameters = new Rc2Parameters()
				.setKeySize(Rc2Parameters.KEY_SIZE_128)
				.setBlockMode(Rc2Parameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testRc4() throws GeneralSecurityException {
		final Rc4Parameters parameters = new Rc4Parameters()
				.setKeySize(Rc2Parameters.KEY_SIZE_128)
				.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testRsa() throws GeneralSecurityException {
		final KeyPair keyPair = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.KEY_SIZE_512,
			RsaParameters.ALGORITHM_RSA);
		final RsaParameters parameters = new RsaParameters()
			.setEncryptionKey(keyPair.getPublic())
			.setDecryptionKey(keyPair.getPrivate())
			.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
			.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
			;

		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

//	/**
//	 * @throws GeneralSecurityException
//	 */
//	@Test
//	public void testElGamal() throws GeneralSecurityException {
//		final Provider provider = new BouncyCastleProvider();
//		final KeyPair keyPair = CryptoUtil.generateAsymmetricKeyPair(ElGamalParameters.KEY_SIZE_256,
//			ElGamalParameters.ALGORITHM_ELGAMAL, null, provider);
//		final ElGamalParameters parameters = new ElGamalParameters()
//			.setEncryptionKey(keyPair.getPublic())
//			.setDecryptionKey(keyPair.getPrivate())
//			.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
//			.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
//			.setProvider(provider)
//			;
//
//		encryptor = new Encryptor(Base64Encoder.getInstance())
//				.setAlgorithmParameters(parameters);
//		encryptor.initialize();
//
//		final String txt = "abcd";
//		final String enc = encryptor.encrypt(txt);
//		assertEquals(txt, encryptor.decrypt(enc));
//	}

	private static class EncryptThread extends Thread {

		/**
		 * {@inheritDoc}
		 * @see java.lang.Thread#run()
		 */
		@Override
		public void run() {
			try {
				for (int i=0; i<50; i++) {
					final String enc = encryptor.encrypt(TEST_TEXT);
					assertEquals(TEST_TEXT, encryptor.decrypt(enc));
				}
			}
			catch (final Exception e) {
				e.printStackTrace();
			}
		}

	}

}
