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
package org.antfarmer.ejce.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.TimeZone;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.ValueEncryptorInterface;
import org.antfarmer.ejce.encoder.Base32Encoder;
import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.exception.MacDisagreementException;
import org.antfarmer.ejce.parameter.AbstractBlockCipherParameters;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.parameter.BlowfishParameters;
import org.antfarmer.ejce.parameter.CamelliaParameters;
import org.antfarmer.ejce.parameter.DesEdeParameters;
import org.antfarmer.ejce.parameter.DesParameters;
import org.antfarmer.ejce.parameter.ElGamalParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.parameter.Rc2Parameters;
import org.antfarmer.ejce.parameter.Rc4Parameters;
import org.antfarmer.ejce.parameter.Rc5Parameters;
import org.antfarmer.ejce.parameter.Rc6Parameters;
import org.antfarmer.ejce.parameter.RsaParameters;
import org.antfarmer.ejce.parameter.SerpentParameters;
import org.antfarmer.ejce.parameter.TeaParameters;
import org.antfarmer.ejce.parameter.TwofishParameters;
import org.antfarmer.ejce.parameter.XteaParameters;
import org.antfarmer.ejce.parameter.key_loader.KeyLoader;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;
import org.antfarmer.ejce.util.ByteUtil;
import org.antfarmer.ejce.util.CryptoUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

	private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void threadSafetyTest() throws Throwable {

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
			threads[i].join();
			if (threads[i].exception != null) {
				throw threads[i].exception;
			}
		}
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptAndEncode(null));
		assertNull(encryptor.decryptAndDecode(null));

		assertNull(encryptor.encrypt((byte[]) null));
		assertNull(encryptor.decrypt((byte[]) null));

		assertNull(encryptor.encrypt((String) null));
		assertNull(encryptor.decrypt((String) null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptBoolean(null));
		assertNull(encryptor.decryptBoolean(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptCharacter(null));
		assertNull(encryptor.decryptCharacter(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptDouble(null));
		assertNull(encryptor.decryptDouble(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptFloat(null));
		assertNull(encryptor.decryptFloat(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptInteger(null));
		assertNull(encryptor.decryptInteger(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptLong(null));
		assertNull(encryptor.decryptLong(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 * @throws IOException IOException
	 * @throws ClassNotFoundException ClassNotFoundException
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

		assertNull(encryptor.encryptObject(null));
		assertNull(encryptor.decryptObject(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertNull(encryptor.encryptShort(null));
		assertNull(encryptor.decryptShort(null));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 * @throws IOException IOException
	 * @throws ClassNotFoundException ClassNotFoundException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testAesBlank() throws GeneralSecurityException {
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

		String enc = encryptor.encrypt("");
		assertEquals("", encryptor.decrypt(enc));

		enc = encryptor.encrypt((String) null);
		assertEquals(null, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testAesGcm() throws GeneralSecurityException {
		final AesParameters parameters = new AesParameters()
				.setKeySize(AesParameters.KEY_SIZE_256)
				.setBlockMode(AesParameters.BLOCK_MODE_GCM)
				.setPadding(AesParameters.PADDING_PKCS5)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testAesGcmTagLengths() throws GeneralSecurityException {
		final int[] lengths = {
				AesParameters.GCM_AUTH_TAG_LEN_96,
				AesParameters.GCM_AUTH_TAG_LEN_104,
				AesParameters.GCM_AUTH_TAG_LEN_112,
				AesParameters.GCM_AUTH_TAG_LEN_120,
				AesParameters.GCM_AUTH_TAG_LEN_128
		};

		for (final int len : lengths) {
			final AesParameters parameters = new AesParameters()
					.setKeySize(AesParameters.KEY_SIZE_256)
					.setBlockMode(AesParameters.BLOCK_MODE_GCM)
					.setGcmTagLen(len)
					.setPadding(AesParameters.PADDING_PKCS5)
					;
			encryptor = new Encryptor(Base64Encoder.getInstance())
					.setAlgorithmParameters(parameters);
			encryptor.initialize();

			final String enc = encryptor.encrypt(TEST_TEXT);
			assertEquals(TEST_TEXT, encryptor.decrypt(enc));
		}
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testAesMacs() throws GeneralSecurityException {
		final String[] macs = {
				AesParameters.MAC_ALGORITHM_HMAC_MD5,
				AesParameters.MAC_ALGORITHM_HMAC_SHA1,
				AesParameters.MAC_ALGORITHM_HMAC_SHA224,
				AesParameters.MAC_ALGORITHM_HMAC_SHA256,
				AesParameters.MAC_ALGORITHM_HMAC_SHA384,
				AesParameters.MAC_ALGORITHM_HMAC_SHA512,
				AesParameters.MAC_ALGORITHM_HMAC_SHA512_224,
				AesParameters.MAC_ALGORITHM_HMAC_SHA512_256,
				AesParameters.MAC_ALGORITHM_HMAC_SHA3_224,
				AesParameters.MAC_ALGORITHM_HMAC_SHA3_256,
				AesParameters.MAC_ALGORITHM_HMAC_SHA3_384,
				AesParameters.MAC_ALGORITHM_HMAC_SHA3_512
		};


		for (final String mac : macs) {
			final AesParameters parameters = new AesParameters()
					.setKeySize(AesParameters.KEY_SIZE_128)
					.setBlockMode(AesParameters.BLOCK_MODE_CFB)
					.setBlockSize(32)
					.setMacAlgorithm(mac)
					.setMacKeySize(AesParameters.MAC_KEY_SIZE_128)
					.setProvider(BC_PROVIDER)
					;
			encryptor = new Encryptor(Base64Encoder.getInstance())
					.setAlgorithmParameters(parameters);
			encryptor.initialize();

			final String enc = encryptor.encrypt(TEST_TEXT);
			assertEquals(TEST_TEXT, encryptor.decrypt(enc));
		}
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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
					@Override
					public void generateSalt(final byte[] saltData) {
						System.arraycopy(salt, 0, saltData, 0, salt.length);
					}
				})
				.setSaltMatcher(new SaltMatcher() {
					@Override
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
	 * @throws GeneralSecurityException GeneralSecurityException
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

	@Test
	public void testBlowfishKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(BlowfishParameters.ALGORITHM_BLOWFISH);
		final BlowfishParameters parameters = new BlowfishParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
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

	@Test
	public void testTwofish() throws GeneralSecurityException {
		final TwofishParameters parameters = new TwofishParameters()
				.setKeySize(TwofishParameters.KEY_SIZE_128)
				.setBlockMode(TwofishParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(TwofishParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(TwofishParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testTwofishKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(TwofishParameters.ALGORITHM_TWOFISH, null, BC_PROVIDER);
		final TwofishParameters parameters = new TwofishParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setBlockMode(TwofishParameters.BLOCK_MODE_GCM)
				.setPadding(TwofishParameters.PADDING_NONE)
				.setBlockSize(32)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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

	@Test
	public void testDesEdeKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(DesEdeParameters.ALGORITHM_TRIPLE_DES);
		final DesEdeParameters parameters = new DesEdeParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testPbeKey() throws GeneralSecurityException {

		final Key key = CryptoUtil.getSecretKeyFromTextKey(PBE_KEY, PbeParameters.ALGORITHM_PBE_MD5_DES);

		final PbeParameters parameters = new PbeParameters()
				.setKey(key)
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
	 * @throws GeneralSecurityException GeneralSecurityException
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

	@Test
	public void testCamellia() throws GeneralSecurityException {
		final CamelliaParameters parameters = new CamelliaParameters()
				.setKeySize(CamelliaParameters.KEY_SIZE_128)
				.setBlockMode(CamelliaParameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(CamelliaParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(CamelliaParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testCamelliaKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(CamelliaParameters.ALGORITHM_CAMELLIA, null, BC_PROVIDER);
		final CamelliaParameters parameters = new CamelliaParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setBlockMode(CamelliaParameters.BLOCK_MODE_GCM)
				.setPadding(CamelliaParameters.PADDING_NONE)
				.setBlockSize(32)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc2() throws GeneralSecurityException {
		final Rc2Parameters parameters = new Rc2Parameters()
				.setKeySize(Rc2Parameters.KEY_SIZE_128)
				.setBlockMode(Rc2Parameters.BLOCK_MODE_CFB)
				.setBlockSize(32)
				.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc2Key() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(Rc2Parameters.ALGORITHM_RC2);

		final Rc2Parameters parameters = new Rc2Parameters(Base32Encoder.getInstance())
				.setKey(Base32Encoder.getInstance().encode(key.getEncoded()))
				.setBlockMode(Rc2Parameters.BLOCK_MODE_CFB)
				.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc4() throws GeneralSecurityException {
		final Rc4Parameters parameters = new Rc4Parameters()
				.setKeySize(Rc4Parameters.KEY_SIZE_128)
				.setMacAlgorithm(Rc4Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc4Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc4Key() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(Rc4Parameters.ALGORITHM_RC4);
		final Rc4Parameters parameters = new Rc4Parameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setMacAlgorithm(Rc4Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc4Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc5() throws GeneralSecurityException {
		final Rc5Parameters parameters = new Rc5Parameters()
				.setKeySize(Rc5Parameters.KEY_SIZE_128)
				.setMacAlgorithm(Rc5Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc5Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc5Key() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(Rc5Parameters.ALGORITHM_RC5, null, BC_PROVIDER);
		final Rc5Parameters parameters = new Rc5Parameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setMacAlgorithm(Rc5Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc5Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc6() throws GeneralSecurityException {
		final Rc6Parameters parameters = new Rc6Parameters()
				.setKeySize(Rc6Parameters.KEY_SIZE_128)
				.setMacAlgorithm(Rc6Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc6Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testRc6Key() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(Rc6Parameters.ALGORITHM_RC6, null, BC_PROVIDER);
		final Rc6Parameters parameters = new Rc6Parameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setMacAlgorithm(Rc6Parameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(Rc6Parameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testSerpent() throws GeneralSecurityException {
		final SerpentParameters parameters = new SerpentParameters()
				.setKeySize(SerpentParameters.KEY_SIZE_128)
				.setMacAlgorithm(SerpentParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(SerpentParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testSerpentKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(SerpentParameters.ALGORITHM_SERPENT, null, BC_PROVIDER);
		final SerpentParameters parameters = new SerpentParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setMacAlgorithm(SerpentParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(SerpentParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testTea() throws GeneralSecurityException {
		final TeaParameters parameters = new TeaParameters()
				.setKeySize(TeaParameters.KEY_SIZE_128)
				.setMacAlgorithm(TeaParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(TeaParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testTeaKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(TeaParameters.ALGORITHM_TEA, null, BC_PROVIDER);
		final TeaParameters parameters = new TeaParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setMacAlgorithm(TeaParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(TeaParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testXtea() throws GeneralSecurityException {
		final XteaParameters parameters = new XteaParameters()
				.setKeySize(XteaParameters.KEY_SIZE_128)
				.setMacAlgorithm(XteaParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(XteaParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	@Test
	public void testXteaKey() throws GeneralSecurityException {
		final Key key = CryptoUtil.generateSecretKey(XteaParameters.ALGORITHM_XTEA, null, BC_PROVIDER);
		final XteaParameters parameters = new XteaParameters(Base64Encoder.getInstance())
				.setKey(Base64Encoder.getInstance().encode(key.getEncoded()))
				.setMacAlgorithm(XteaParameters.MAC_ALGORITHM_HMAC_SHA1)
				.setMacKeySize(XteaParameters.MAC_KEY_SIZE_128)
				.setProvider(BC_PROVIDER)
				;
		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String enc = encryptor.encrypt(TEST_TEXT);
		assertEquals(TEST_TEXT, encryptor.decrypt(enc));
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
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

		assertEquals(AbstractBlockCipherParameters.BLOCK_MODE_ECB, parameters.getBlockType());
		assertNull(parameters.getPadding());
	}

	/**
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testRsaWithPadding() throws GeneralSecurityException {
		final KeyPair keyPair = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.KEY_SIZE_1024,
			RsaParameters.ALGORITHM_RSA);
		final RsaParameters parameters = new RsaParameters()
			.setEncryptionKey(keyPair.getPublic())
			.setDecryptionKey(keyPair.getPrivate())
			.setBlockType(AbstractBlockCipherParameters.BLOCK_MODE_ECB)
			.setPadding(RsaParameters.PADDING_PKCS1)
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testRsaGenKey() throws GeneralSecurityException {
		final RsaParameters parameters = new RsaParameters(Base64Encoder.getInstance())
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testRsaKeyLoader() throws GeneralSecurityException {
		final KeyPair keyPair = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.KEY_SIZE_512,
			RsaParameters.ALGORITHM_RSA);
		final RsaParameters parameters = new RsaParameters()
			.setEncryptionKeyLoader(new KeyLoader() {
				@Override
				public Key loadKey(final String algorithm) {
					return keyPair.getPublic();
				}
			})
			.setDecryptionKeyLoader(new KeyLoader() {
				@Override
				public Key loadKey(final String algorithm) {
					return keyPair.getPrivate();
				}
			})
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
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	@Test
	public void testElGamal() throws GeneralSecurityException {
		final KeyPair keyPair = CryptoUtil.generateAsymmetricKeyPair(ElGamalParameters.KEY_SIZE_256,
			ElGamalParameters.ALGORITHM_ELGAMAL, null, BC_PROVIDER);
		final ElGamalParameters parameters = new ElGamalParameters()
			.setEncryptionKey(keyPair.getPublic())
			.setDecryptionKey(keyPair.getPrivate())
			.setMacAlgorithm(Rc2Parameters.MAC_ALGORITHM_HMAC_SHA1)
			.setMacKeySize(Rc2Parameters.MAC_KEY_SIZE_128)
			.setProvider(BC_PROVIDER)
			;

		encryptor = new Encryptor(Base64Encoder.getInstance())
				.setAlgorithmParameters(parameters);
		encryptor.initialize();

		final String txt = "abcd";
		final String enc = encryptor.encrypt(txt);
		assertEquals(txt, encryptor.decrypt(enc));
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testWrongKeyLoader() {

		new AesParameters().setKeyLoader(new String());
	}

//	@Test
//	public void testAlgos() {
//		final Set<String> ciphers = new TreeSet<String>();
//		for (final Provider provider : Security.getProviders()) {
//			System.out.println(provider.getName());
//			for (final String key : provider.stringPropertyNames()) {
//				final String cipherName = provider.getProperty(key);
//				ciphers.add(cipherName);
////				System.out.println("\t"/* + key */ + "\t" + cipherName);
//			}
//		}
//
//		for (final String name : ciphers) {
//			System.out.println("------- " + name);
//		}
//	}

	private static class EncryptThread extends Thread {
		private Throwable exception;

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
			catch (final Throwable e) {
				exception = e;
				e.printStackTrace();
			}
		}

	}

}
