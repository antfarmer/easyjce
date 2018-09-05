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
package org.antfarmer.ejce.test.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.util.MessageDigestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class MessageDigestUtilTest {

	private static final int HASH_COUNT = 5;
	private static final int MAX_INPUT_SIZE = 4096;
	private static final Random random = new SecureRandom();

	@Test
	public void testHashBytes() throws NoSuchAlgorithmException, NoSuchProviderException {

		byte[] input;
		byte[] output;

		final Map<String, Integer> algoMap = new LinkedHashMap<String, Integer>();
		algoMap.put(MessageDigestUtil.ALGORITHM_MD2, 16);
		algoMap.put(MessageDigestUtil.ALGORITHM_MD5, 16);
		algoMap.put(MessageDigestUtil.ALGORITHM_SHA1, 20);
		algoMap.put(MessageDigestUtil.ALGORITHM_SHA2_224, 28);
		algoMap.put(MessageDigestUtil.ALGORITHM_SHA2_256, 32);
		algoMap.put(MessageDigestUtil.ALGORITHM_SHA2_384, 48);
		algoMap.put(MessageDigestUtil.ALGORITHM_SHA2_512, 64);

		for (final Entry<String, Integer> algo : algoMap.entrySet()) {
			for (int i = 0; i < HASH_COUNT; i++) {
				input = new byte[random.nextInt(MAX_INPUT_SIZE) + 1];
				random.nextBytes(input);

				output = MessageDigestUtil.hashBytes(input, algo.getKey());

				assertEquals(algo.getValue().intValue(), output.length);
				assertFalse(Arrays.equals(input, output));
				System.out.print(output.length + " ");
				System.out.println(Base64Encoder.getInstance().encode(output));
			}
		}
	}


	@Test
	public void testHashBytesWithProvider() throws NoSuchAlgorithmException, NoSuchProviderException {

		byte[] input;
		byte[] output;

		final Map<String, Integer> extAlgoMap = new LinkedHashMap<String, Integer>();
		extAlgoMap.put(MessageDigestUtil.ALGORITHM_SHA2_512_224, 28);
		extAlgoMap.put(MessageDigestUtil.ALGORITHM_SHA2_512_256, 32);
		extAlgoMap.put(MessageDigestUtil.ALGORITHM_SHA3_224, 28);
		extAlgoMap.put(MessageDigestUtil.ALGORITHM_SHA3_256, 32);
		extAlgoMap.put(MessageDigestUtil.ALGORITHM_SHA3_384, 48);
		extAlgoMap.put(MessageDigestUtil.ALGORITHM_SHA3_512, 64);

		final Provider provider = new BouncyCastleProvider();
		for (final Entry<String, Integer> algo : extAlgoMap.entrySet()) {
			for (int i = 0; i < HASH_COUNT; i++) {
				input = new byte[random.nextInt(MAX_INPUT_SIZE) + 1];
				random.nextBytes(input);

				output = MessageDigestUtil.hashBytes(input, algo.getKey(), provider, null);

				assertEquals(algo.getValue().intValue(), output.length);
				assertFalse(Arrays.equals(input, output));
				System.out.print(output.length + " ");
				System.out.println(Base64Encoder.getInstance().encode(output));
			}
		}
	}

//	@Test
//	public void listAlgos() {
//		final Provider[] providers = Security.getProviders();
//		for (final Provider provider : providers) {
//			showHashAlgorithms(provider, MessageDigest.class);
//		}
//		showHashAlgorithms(new BouncyCastleProvider(), MessageDigest.class);
//	}
//
//	private static final void showHashAlgorithms(final Provider prov, final Class<?> typeClass) {
//		final String type = typeClass.getSimpleName();
//
//		final List<Service> algos = new ArrayList<Service>();
//
//		final Set<Service> services = prov.getServices();
//		for (final Service service : services) {
//			if (service.getType().equalsIgnoreCase(type)) {
//				algos.add(service);
//			}
//		}
//
//		if (!algos.isEmpty()) {
//			System.out.printf(" --- Provider %s, version %.2f --- %n", prov.getName(), prov.getVersion());
//			for (final Service service : algos) {
//				final String algo = service.getAlgorithm();
//				System.out.printf("Algorithm name: \"%s\"%n", algo);
//			}
//		}
//
//		// --- find aliases (inefficiently)
//		final Set<Object> keys = prov.keySet();
//		for (final Object key : keys) {
//			final String prefix = "Alg.Alias." + type + ".";
//			if (key.toString().startsWith(prefix)) {
//				final String value = prov.get(key.toString()).toString();
//				System.out.printf("Alias: \"%s\" -> \"%s\"%n", key.toString().substring(prefix.length()), value);
//			}
//		}
//	}

}
