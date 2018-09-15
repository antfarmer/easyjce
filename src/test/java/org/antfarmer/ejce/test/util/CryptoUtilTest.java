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
package org.antfarmer.ejce.test.util;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;

import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.parameter.AbstractAlgorithmParameters;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.parameter.RsaParameters;
import org.antfarmer.ejce.util.CryptoUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;


/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class CryptoUtilTest {

	private static final Random random = new Random();

	@Test
	public void testKeySize() throws NoSuchAlgorithmException {
		final int keySize = AbstractAlgorithmParameters.KEY_SIZE_128;
		final Key key = CryptoUtil.generateSecretKey(keySize, AesParameters.ALGORITHM_AES);
		assertEquals(keySize, key.getEncoded().length * Byte.SIZE);
	}

	@Test
	public void testPbeKeySize() {
		final String password = "password_DROWSSAP";
		final Key key = CryptoUtil.getSecretKeyFromTextKey(password, PbeParameters.ALGORITHM_PBE_MD5_DES);
		assertEquals(password.length(), key.getEncoded().length);


		final Base64Encoder encoder = Base64Encoder.getInstance();
		final Key key2 = CryptoUtil.getSecretKeyFromTextKey(encoder.encode(password.getBytes()), PbeParameters.ALGORITHM_PBE_MD5_DES, encoder);
		assertEquals(password.length(), key2.getEncoded().length);
	}

	@Test
	public void testGenKeys() throws NoSuchAlgorithmException, NoSuchProviderException {
		final Key simpleKey = CryptoUtil.generateSecretKey(AesParameters.ALGORITHM_AES);
		System.out.println(Base64Encoder.getInstance().encode(simpleKey.getEncoded()));
		assertEquals(AesParameters.KEY_SIZE_128, simpleKey.getEncoded().length * Byte.SIZE);

		final int keySize = AbstractAlgorithmParameters.KEY_SIZE_192;
		final Key key = CryptoUtil.generateSecretKey(keySize, AesParameters.ALGORITHM_AES);
		System.out.println(Base64Encoder.getInstance().encode(key.getEncoded()));
		assertEquals(keySize, key.getEncoded().length * Byte.SIZE);

		final int macKeySize = AbstractAlgorithmParameters.MAC_KEY_SIZE_128;
		final Key macKey = CryptoUtil.generateSecretKey(macKeySize, AesParameters.MAC_ALGORITHM_HMAC_SHA1);
		System.out.println(Base64Encoder.getInstance().encode(macKey.getEncoded()));
		assertEquals(macKeySize, macKey.getEncoded().length * Byte.SIZE);

		final int keySize2 = AbstractAlgorithmParameters.KEY_SIZE_256;
		final Key key2 = CryptoUtil.generateSecretKey(keySize2, AesParameters.ALGORITHM_AES, null, new BouncyCastleProvider());
		System.out.println(Base64Encoder.getInstance().encode(key2.getEncoded()));
		assertEquals(keySize2, key2.getEncoded().length * Byte.SIZE);
	}

	@Test
	public void testGenAsymmetricKeys() throws NoSuchAlgorithmException, NoSuchProviderException {
		final KeyPair simpleKey = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.ALGORITHM_RSA);
		System.out.println(Base64Encoder.getInstance().encode(simpleKey.getPublic().getEncoded()));

		final KeyPair key1 = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.KEY_SIZE_768, RsaParameters.ALGORITHM_RSA);
		System.out.println(Base64Encoder.getInstance().encode(key1.getPublic().getEncoded()));
		assertEquals(1008, key1.getPublic().getEncoded().length * Byte.SIZE);

		final KeyPair key2 = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.KEY_SIZE_512, RsaParameters.ALGORITHM_RSA, null, new BouncyCastleProvider());
		System.out.println(Base64Encoder.getInstance().encode(key2.getPublic().getEncoded()));
		assertEquals(752, key2.getPublic().getEncoded().length * Byte.SIZE);
	}

	@Test
	public void testKeySpec() throws InvalidKeySpecException, NoSuchAlgorithmException {
		final RSAPublicKeySpec pub = new RSAPublicKeySpec(
				new BigInteger(1024, 1, random),
				new BigInteger(512, 1, random)
		);
		final PublicKey pubKey = CryptoUtil.createPublicKey(RsaParameters.ALGORITHM_RSA, pub);
		assertEquals(1792, pubKey.getEncoded().length * Byte.SIZE);

		final RSAPrivateKeySpec prv = new RSAPrivateKeySpec(
				new BigInteger(512, 1, random),
				new BigInteger(768, 1, random)
		);
		final PrivateKey prvKey = CryptoUtil.createPrivateKey(RsaParameters.ALGORITHM_RSA, prv);
		assertEquals(1712, prvKey.getEncoded().length * Byte.SIZE);

		final RSAPublicKeySpec pubks = CryptoUtil.getKeySpec(pubKey, RSAPublicKeySpec.class);
		assertEquals(pub.getModulus(), pubks.getModulus());
		assertEquals(pub.getPublicExponent(), pubks.getPublicExponent());

		final RSAPrivateKeySpec result = CryptoUtil.getKeySpec(prvKey, RSAPrivateKeySpec.class);
		assertEquals(prv.getModulus(), result.getModulus());
		assertEquals(prv.getPrivateExponent(), result.getPrivateExponent());
	}
}
