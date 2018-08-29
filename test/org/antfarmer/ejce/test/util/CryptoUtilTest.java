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

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import org.antfarmer.ejce.parameter.AbstractAlgorithmParameters;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.util.CryptoUtil;
import org.junit.Test;


/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class CryptoUtilTest {

	/**
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testKeySize() throws NoSuchAlgorithmException {
		final int keySize = AbstractAlgorithmParameters.KEY_SIZE_128;
		final Key key = CryptoUtil.generateSecretKey(keySize, AesParameters.ALGORITHM_AES);
		assertEquals(keySize, key.getEncoded().length * Byte.SIZE);
	}

	/**
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testPbeKeySize() {
		final String password = "password_DROWSSAP";
		final Key key = CryptoUtil.getSecretKeyFromTextKey(password, PbeParameters.ALGORITHM_PBE_MD5_DES);
		assertEquals(password.length(), key.getEncoded().length);
	}
}
