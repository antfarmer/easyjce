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
import static org.junit.Assert.assertSame;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.EncryptorStore;
import org.antfarmer.ejce.encoder.Base32Encoder;
import org.antfarmer.ejce.encoder.Base64UrlEncoder;
import org.antfarmer.ejce.encoder.HexEncoder;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.parameter.BlowfishParameters;
import org.antfarmer.ejce.parameter.DesEdeParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.parameter.RsaParameters;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;
import org.antfarmer.ejce.password.ConfigurablePasswordEncoder;
import org.antfarmer.ejce.password.PasswordEncoderStore;
import org.antfarmer.ejce.password.encoder.spring.SpringBcryptEncoder;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class ConfigurerUtilTest {

	/**
	 *
	 */
	@Test
	public void testSetStoredEncryptor() {
		final DesEdeParameters parameters = new DesEdeParameters();
		parameters.setKeySize(DesEdeParameters.KEY_SIZE_DES_EDE_112)
				.setBlockMode(DesEdeParameters.BLOCK_MODE_CFB)
				.setPadding(DesEdeParameters.PADDING_PKCS5)
				.setMacAlgorithm(DesEdeParameters.MAC_ALGORITHM_HMAC_MD5)
				.setMacKeySize(DesEdeParameters.MAC_KEY_SIZE_128);
		final Encryptor encryptor = new Encryptor().setAlgorithmParameters(parameters);
		EncryptorStore.add("name", encryptor);

		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY, "name");

		assertSame(encryptor, ConfigurerUtil.configureEncryptor(properties));
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testSetParameterValues() throws Exception {
		final String key = Base32Encoder.getInstance().encode("SMOKESOMEOFMYTIE".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("SMOKEAJAYINTHEGOODOLUSA".getBytes());
		final String saltSize = "6";
		final String iterations = "700";
		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_ENCODER_CLASS, HexEncoder.class.getName());
		properties.put(ConfigurerUtil.KEY_PARAM_CLASS, PbeParameters.class.getName());
		properties.put(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.put(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.put(ConfigurerUtil.KEY_ALGORITHM, PbeParameters.ALGORITHM_PBE_MD5_DES);
		properties.put(ConfigurerUtil.KEY_PROVIDER_CLASS, sun.security.provider.Sun.class.getName());
		properties.put(ConfigurerUtil.KEY_MAC_ALGORITHM, PbeParameters.MAC_ALGORITHM_HMAC_MD5);
		properties.put(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.put(ConfigurerUtil.KEY_BLOCK_MODE, PbeParameters.BLOCK_MODE_OFB);
		properties.put(ConfigurerUtil.KEY_PADDING, PbeParameters.PADDING_PKCS5);
		properties.put(ConfigurerUtil.KEY_SALT_SIZE, saltSize);
		properties.put(ConfigurerUtil.KEY_ITERATION_COUNT, iterations);
		properties.put(ConfigurerUtil.KEY_SALT_GENERATOR, DefaultSaltGenerator.class.getName());
		properties.put(ConfigurerUtil.KEY_SALT_MATCHER, DefaultSaltMatcher.class.getName());

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final PbeParameters parameters = (PbeParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(HexEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(Charset.forName("UTF-8"), encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(PbeParameters.ALGORITHM_PBE_MD5_DES, parameters.getAlgorithm());
		assertEquals(sun.security.provider.Sun.class, parameters.getProvider().getClass());
		assertEquals(PbeParameters.MAC_ALGORITHM_HMAC_MD5, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(PbeParameters.BLOCK_MODE_OFB, parameters.getBlockMode());
		assertEquals(PbeParameters.GCM_AUTH_TAG_LEN_128, parameters.getGcmTagLen());
		assertEquals(PbeParameters.PADDING_PKCS5, parameters.getPadding());
		assertEquals(Integer.valueOf(8), (Integer)parameters.getBlockSize());
		assertEquals(Integer.valueOf(saltSize), (Integer)parameters.getSaltSize());
		assertEquals(Integer.valueOf(iterations), (Integer)parameters.getIterationCount());
		assertEquals(DefaultSaltGenerator.class, ReflectionUtil.getFieldValue(parameters, "saltGenerator").getClass());
		assertEquals(DefaultSaltMatcher.class, ReflectionUtil.getFieldValue(parameters, "saltMatcher").getClass());
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testSetParameterValues2() throws Exception {

		final Charset cs = Charset.forName("US-ASCII");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_ENCODER_CLASS, Base64UrlEncoder.class.getName());
		properties.put(ConfigurerUtil.KEY_CHARSET, cs.name());
		properties.put(ConfigurerUtil.KEY_PARAM_CLASS, BlowfishParameters.class.getName());
		properties.put(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.put(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.put(ConfigurerUtil.KEY_PROVIDER_NAME, providerName);
		properties.put(ConfigurerUtil.KEY_MAC_ALGORITHM, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.put(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.put(ConfigurerUtil.KEY_BLOCK_MODE, BlowfishParameters.BLOCK_MODE_CFB);
		properties.put(ConfigurerUtil.KEY_BLOCK_SIZE, blockSize);
		properties.put(ConfigurerUtil.KEY_PADDING, BlowfishParameters.PADDING_NONE);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final BlowfishParameters parameters = (BlowfishParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base64UrlEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(providerName, parameters.getProviderName());
		assertEquals(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(BlowfishParameters.BLOCK_MODE_CFB, parameters.getBlockMode());
		assertEquals(Integer.valueOf(blockSize), (Integer)parameters.getBlockSize());
		assertEquals(BlowfishParameters.PADDING_NONE, parameters.getPadding());
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testSetParameterValues3() throws Exception {

		final Charset cs = Charset.forName("US-ASCII");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_ENCODER_CLASS, Base64UrlEncoder.class.getName());
		properties.put(ConfigurerUtil.KEY_CHARSET, cs.name());
		properties.put(ConfigurerUtil.KEY_PARAM_CLASS, BlowfishParameters.class.getName());
		properties.put(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.put(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.put(ConfigurerUtil.KEY_PROVIDER_NAME, providerName);
		properties.put(ConfigurerUtil.KEY_MAC_ALGORITHM, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.put(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.put(ConfigurerUtil.KEY_BLOCK_MODE, BlowfishParameters.BLOCK_MODE_GCM);
		properties.put(ConfigurerUtil.KEY_BLOCK_SIZE, blockSize);
		properties.put(ConfigurerUtil.KEY_GCM_TAG_LEN, String.valueOf(BlowfishParameters.GCM_AUTH_TAG_LEN_96));
		properties.put(ConfigurerUtil.KEY_PADDING, BlowfishParameters.PADDING_NONE);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final BlowfishParameters parameters = (BlowfishParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base64UrlEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(providerName, parameters.getProviderName());
		assertEquals(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(BlowfishParameters.BLOCK_MODE_GCM, parameters.getBlockMode());
		assertEquals(BlowfishParameters.GCM_AUTH_TAG_LEN_96, parameters.getGcmTagLen());
		assertEquals(Integer.valueOf(8), (Integer)parameters.getBlockSize());
		assertEquals(BlowfishParameters.PADDING_NONE, parameters.getPadding());
	}

	/**
	 *
	 */
	@Test
	public void testSetStoredEncryptorViaSysProps() {
		final DesEdeParameters parameters = new DesEdeParameters();
		parameters.setKeySize(DesEdeParameters.KEY_SIZE_DES_EDE_112)
				.setBlockMode(DesEdeParameters.BLOCK_MODE_CFB)
				.setPadding(DesEdeParameters.PADDING_PKCS5)
				.setMacAlgorithm(DesEdeParameters.MAC_ALGORITHM_HMAC_MD5)
				.setMacKeySize(DesEdeParameters.MAC_KEY_SIZE_128);
		final Encryptor encryptor = new Encryptor().setAlgorithmParameters(parameters);
		EncryptorStore.add("name", encryptor);

		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		final String propPrefix = "ejce.encryptor1";
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY), "name");

		assertSame(encryptor, ConfigurerUtil.configureEncryptor(properties.getProperties(), propPrefix));

		properties.rollback();
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testSetParameterValuesViaSysProps() throws Exception {
		final Charset cs = Charset.forName("UTF-16");
		final String key = Base32Encoder.getInstance().encode("SMOKESOMEOFMYTIE".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("SMOKEAJAYINTHEGOODOLUSA".getBytes());
		final String saltSize = "6";
		final String iterations = "700";
		final String propPrefix = "ejce.encryptor1";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), HexEncoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), PbeParameters.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ALGORITHM), PbeParameters.ALGORITHM_PBE_MD5_DES);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_CLASS), sun.security.provider.Sun.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), PbeParameters.MAC_ALGORITHM_HMAC_MD5);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), PbeParameters.BLOCK_MODE_OFB);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), PbeParameters.PADDING_PKCS5);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_SALT_SIZE), saltSize);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ITERATION_COUNT), iterations);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties.getProperties(), propPrefix);
		final PbeParameters parameters = (PbeParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(HexEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(PbeParameters.ALGORITHM_PBE_MD5_DES, parameters.getAlgorithm());
		assertEquals(sun.security.provider.Sun.class, parameters.getProvider().getClass());
		assertEquals(PbeParameters.MAC_ALGORITHM_HMAC_MD5, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(PbeParameters.BLOCK_MODE_OFB, parameters.getBlockMode());
		assertEquals(PbeParameters.GCM_AUTH_TAG_LEN_128, parameters.getGcmTagLen());
		assertEquals(PbeParameters.PADDING_PKCS5, parameters.getPadding());
		assertEquals(Integer.valueOf(saltSize), (Integer)parameters.getSaltSize());
		assertEquals(Integer.valueOf(iterations), (Integer)parameters.getIterationCount());

		properties.rollback();
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testSetParameterValues2ViaSysProps() throws Exception {

		final Charset cs = Charset.forName("ISO-8859-1");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final String propPrefix = "ejce.encryptor1";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), Base64UrlEncoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), BlowfishParameters.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_NAME), providerName);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), BlowfishParameters.BLOCK_MODE_OFB);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_SIZE), blockSize);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), BlowfishParameters.PADDING_NONE);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties.getProperties(), propPrefix);
		final BlowfishParameters parameters = (BlowfishParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base64UrlEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(providerName, parameters.getProviderName());
		assertEquals(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(BlowfishParameters.BLOCK_MODE_OFB, parameters.getBlockMode());
		assertEquals(Integer.valueOf(blockSize), (Integer)parameters.getBlockSize());
		assertEquals(BlowfishParameters.PADDING_NONE, parameters.getPadding());

		properties.rollback();
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testSetParameterValues3ViaSysProps() throws Exception {

		final Charset cs = Charset.forName("ISO-8859-1");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final String propPrefix = "ejce.encryptor1";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), Base64UrlEncoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), BlowfishParameters.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_NAME), providerName);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), BlowfishParameters.BLOCK_MODE_GCM);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_GCM_TAG_LEN), String.valueOf(BlowfishParameters.GCM_AUTH_TAG_LEN_112));
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_SIZE), blockSize);
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), BlowfishParameters.PADDING_NONE);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties.getProperties(), propPrefix);
		final BlowfishParameters parameters = (BlowfishParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base64UrlEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(providerName, parameters.getProviderName());
		assertEquals(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(BlowfishParameters.BLOCK_MODE_GCM, parameters.getBlockMode());
		assertEquals(BlowfishParameters.GCM_AUTH_TAG_LEN_112, parameters.getGcmTagLen());
		assertEquals(Integer.valueOf(8), (Integer)parameters.getBlockSize());
		assertEquals(BlowfishParameters.PADDING_NONE, parameters.getPadding());

		properties.rollback();
	}

	/**
	 * @throws Exception
	 */
	@Test(expected = EncryptorConfigurationException.class)
	public void testAsymetric() throws Exception {
		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_PARAM_CLASS, RsaParameters.class.getName());
		properties.put(ConfigurerUtil.KEY_ALGORITHM, RsaParameters.ALGORITHM_RSA);

		ConfigurerUtil.loadAlgorithmParameters(properties, null);
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testPswdEncoderParameterValues() throws Exception {
		final String exportKey = "org.antfarmer.test.springPswdEncoder";
		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_PSWD_ENCODER_ADAPTER_CLASS, SpringBcryptEncoder.class.getName());
		properties.put(ConfigurerUtil.KEY_PSWD_ENCODER_STORE_EXPORT_KEY, exportKey);

		final ConfigurablePasswordEncoder encoder = ConfigurerUtil.configurePswdEncoder(properties);

		assertEquals(SpringBcryptEncoder.class, encoder.getClass());
		assertSame(encoder, PasswordEncoderStore.get(exportKey));
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testPswdEncoderViaStore() throws Exception {
		final SpringBcryptEncoder pswdEncoder = new SpringBcryptEncoder();
		PasswordEncoderStore.add("name", pswdEncoder);

		final Properties properties = new Properties();
		properties.put(ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY, "name");

		assertSame(pswdEncoder, ConfigurerUtil.configurePswdEncoder(properties));
	}

	/**
	 *
	 */
	@Test
	public void testPswdEncoderStoredViaSysProps() {
		final SpringBcryptEncoder pswdEncoder = new SpringBcryptEncoder();
		PasswordEncoderStore.add("name", pswdEncoder);

		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		final String propPrefix = "ejce.pswdEncoder1";
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY), "name");

		assertSame(pswdEncoder, ConfigurerUtil.configurePswdEncoder(properties.getProperties(), propPrefix));

		properties.rollback();
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testPswdEncoderParameterValuesViaSysProps() throws Exception {
		final String propPrefix = "ejce.pswdEncoder1";
		final String exportKey = "org.antfarmer.test.springPswdEncoder";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PSWD_ENCODER_ADAPTER_CLASS), SpringBcryptEncoder.class.getName());
		properties.put(getPropertyName(propPrefix, ConfigurerUtil.KEY_PSWD_ENCODER_STORE_EXPORT_KEY), exportKey);

		final ConfigurablePasswordEncoder encoder = ConfigurerUtil.configurePswdEncoder(properties.getProperties(), propPrefix);

		assertEquals(SpringBcryptEncoder.class, encoder.getClass());
		assertSame(encoder, PasswordEncoderStore.get(exportKey));

		properties.rollback();
	}

	private String getPropertyName(final String prefix, final String key) {
		return prefix == null ? key : prefix + "." + key;
	}

	public static class DefaultSaltGenerator implements SaltGenerator {
		/**
		 * {@inheritDoc}
		 */
		@Override
		public void generateSalt(final byte[] saltData) {
			// nothing
		}
	}

	public static class DefaultSaltMatcher implements SaltMatcher {
		/**
		 * {@inheritDoc}
		 */
		@Override
		public void verifySaltMatch(final byte[] cipherSalt) throws GeneralSecurityException {
			// nothing
		}
	}
}
