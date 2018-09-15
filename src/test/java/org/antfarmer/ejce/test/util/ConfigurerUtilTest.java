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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Properties;

import javax.crypto.Cipher;

import org.antfarmer.ejce.Encryptor;
import org.antfarmer.ejce.EncryptorStore;
import org.antfarmer.ejce.encoder.Base32Encoder;
import org.antfarmer.ejce.encoder.Base64Encoder;
import org.antfarmer.ejce.encoder.Base64UrlEncoder;
import org.antfarmer.ejce.encoder.HexEncoder;
import org.antfarmer.ejce.exception.EncryptorConfigurationException;
import org.antfarmer.ejce.parameter.AbstractAlgorithmParameters;
import org.antfarmer.ejce.parameter.AesParameters;
import org.antfarmer.ejce.parameter.BlowfishParameters;
import org.antfarmer.ejce.parameter.CamelliaParameters;
import org.antfarmer.ejce.parameter.DesEdeParameters;
import org.antfarmer.ejce.parameter.PbeParameters;
import org.antfarmer.ejce.parameter.Rc4Parameters;
import org.antfarmer.ejce.parameter.RsaParameters;
import org.antfarmer.ejce.parameter.TwofishParameters;
import org.antfarmer.ejce.parameter.key_loader.KeyLoader;
import org.antfarmer.ejce.parameter.salt.SaltGenerator;
import org.antfarmer.ejce.parameter.salt.SaltMatcher;
import org.antfarmer.ejce.password.ConfigurablePasswordEncoder;
import org.antfarmer.ejce.password.PasswordEncoderStore;
import org.antfarmer.ejce.password.encoder.spring.SpringBcryptEncoder;
import org.antfarmer.ejce.util.ConfigurerUtil;
import org.antfarmer.ejce.util.CryptoUtil;
import org.antfarmer.ejce.util.ReflectionUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Test;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class ConfigurerUtilTest {

	@After
	public void after() {
		EncryptorStore.clear();
		PasswordEncoderStore.clear();
	}

	/**
	 *
	 */
	@Test
	public void testSetStoredEncryptor() {
		final String name = "name";
		final DesEdeParameters parameters = new DesEdeParameters();
		parameters.setKeySize(DesEdeParameters.KEY_SIZE_DES_EDE_112)
				.setBlockMode(DesEdeParameters.BLOCK_MODE_CFB)
				.setPadding(DesEdeParameters.PADDING_PKCS5)
				.setMacAlgorithm(DesEdeParameters.MAC_ALGORITHM_HMAC_MD5)
				.setMacKeySize(DesEdeParameters.MAC_KEY_SIZE_128);
		final Encryptor encryptor = new Encryptor().setAlgorithmParameters(parameters);

		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY, name);

		EncryptorStore.add(name, encryptor);
		assertSame(encryptor, ConfigurerUtil.configureEncryptor(properties));

		// check missing encryptor from store
		EncryptorStore.remove(name);
		Exception ex = null;
		try {
			ConfigurerUtil.configureEncryptor(properties);
		}
		catch (final Exception e) {
			ex = e;
		}
		assertEquals(EncryptorConfigurationException.class, ex.getClass());
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValues() throws Exception {
		final String key = Base32Encoder.getInstance().encode("SMOKESOMEOFMYTIE".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("SMOKEAJAYINTHEGOODOLUSA".getBytes());
		final String saltSize = "6";
		final String iterations = "700";
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_ENCODER_CLASS, HexEncoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, PbeParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.setProperty(ConfigurerUtil.KEY_ALGORITHM, PbeParameters.ALGORITHM_PBE_MD5_DES);
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_CLASS, sun.security.provider.Sun.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_MAC_ALGORITHM, PbeParameters.MAC_ALGORITHM_HMAC_MD5);
		properties.setProperty(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.setProperty(ConfigurerUtil.KEY_BLOCK_MODE, PbeParameters.BLOCK_MODE_OFB);
		properties.setProperty(ConfigurerUtil.KEY_PADDING, PbeParameters.PADDING_PKCS5);
		properties.setProperty(ConfigurerUtil.KEY_SALT_SIZE, saltSize);
		properties.setProperty(ConfigurerUtil.KEY_ITERATION_COUNT, iterations);
		properties.setProperty(ConfigurerUtil.KEY_SALT_GENERATOR, DefaultSaltGenerator.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_SALT_MATCHER, DefaultSaltMatcher.class.getName());

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
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValuesNoPbeConfig() throws Exception {
		final String key = Base32Encoder.getInstance().encode("SMOKESOMEOFMYTIE".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("SMOKEAJAYINTHEGOODOLUSA".getBytes());
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_ENCODER_CLASS, HexEncoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, PbeParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.setProperty(ConfigurerUtil.KEY_ALGORITHM, PbeParameters.ALGORITHM_PBE_MD5_DES);
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_CLASS, sun.security.provider.Sun.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_MAC_ALGORITHM, PbeParameters.MAC_ALGORITHM_HMAC_MD5);
		properties.setProperty(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.setProperty(ConfigurerUtil.KEY_BLOCK_MODE, PbeParameters.BLOCK_MODE_OFB);
		properties.setProperty(ConfigurerUtil.KEY_PADDING, PbeParameters.PADDING_PKCS5);
		properties.setProperty(ConfigurerUtil.KEY_SALT_GENERATOR, DefaultSaltGenerator.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_SALT_MATCHER, DefaultSaltMatcher.class.getName());

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
		assertEquals(DefaultSaltGenerator.class, ReflectionUtil.getFieldValue(parameters, "saltGenerator").getClass());
		assertEquals(DefaultSaltMatcher.class, ReflectionUtil.getFieldValue(parameters, "saltMatcher").getClass());
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValues2() throws Exception {

		final Charset cs = Charset.forName("US-ASCII");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_CHARSET, cs.name());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, BlowfishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_NAME, providerName);
		properties.setProperty(ConfigurerUtil.KEY_MAC_ALGORITHM, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.setProperty(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.setProperty(ConfigurerUtil.KEY_BLOCK_MODE, BlowfishParameters.BLOCK_MODE_CFB);
		properties.setProperty(ConfigurerUtil.KEY_BLOCK_SIZE, blockSize);
		properties.setProperty(ConfigurerUtil.KEY_PADDING, BlowfishParameters.PADDING_NONE);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final BlowfishParameters parameters = (BlowfishParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

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
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValues3() throws Exception {

		final Charset cs = Charset.forName("US-ASCII");
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_ENCODER_CLASS, Base64UrlEncoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CHARSET, cs.name());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, BlowfishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_KEY_LOADER, MyKeyLoader.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_NAME, providerName);
		properties.setProperty(ConfigurerUtil.KEY_MAC_ALGORITHM, BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.setProperty(ConfigurerUtil.KEY_MAC_KEY_LOADER, MyMacKeyLoader.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_BLOCK_MODE, BlowfishParameters.BLOCK_MODE_GCM);
		properties.setProperty(ConfigurerUtil.KEY_BLOCK_SIZE, blockSize);
		properties.setProperty(ConfigurerUtil.KEY_GCM_TAG_LEN, String.valueOf(BlowfishParameters.GCM_AUTH_TAG_LEN_96));
		properties.setProperty(ConfigurerUtil.KEY_PADDING, BlowfishParameters.PADDING_NONE);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final BlowfishParameters parameters = (BlowfishParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");
		parameters.getKey();
		parameters.getMacKey();

		assertEquals(Base64UrlEncoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertArrayEquals(MyKeyLoader.key.getEncoded(), parameters.getKey().getEncoded());
		assertEquals(providerName, parameters.getProviderName());
		assertEquals(BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertArrayEquals(MyMacKeyLoader.key.getEncoded(), parameters.getMacKey().getEncoded());
		assertEquals(BlowfishParameters.BLOCK_MODE_GCM, parameters.getBlockMode());
		assertEquals(BlowfishParameters.GCM_AUTH_TAG_LEN_96, parameters.getGcmTagLen());
		assertEquals(Integer.valueOf(8), (Integer)parameters.getBlockSize());
		assertEquals(BlowfishParameters.PADDING_NONE, parameters.getPadding());
	}

	@Test
	public void testSetParameterValues4() throws Exception {

		final Class<? extends Provider> providerClass = BouncyCastleProvider.class;
		final Charset cs = Charset.forName("UTF-16");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_CHARSET, cs.name());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, Rc4Parameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, key);
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_CLASS, providerClass.getName());
		properties.setProperty(ConfigurerUtil.KEY_MAC_ALGORITHM, Rc4Parameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.setProperty(ConfigurerUtil.KEY_MAC_KEY, macKey);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final Rc4Parameters parameters = (Rc4Parameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertSame(providerClass, parameters.getProvider().getClass());
		assertEquals(Rc4Parameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
	}

	public void testSetParameterValues5() throws Exception {

		final Class<? extends Provider> providerClass = BouncyCastleProvider.class;
		final Charset cs = Charset.forName("UTF-16");
		final KeyPair pair = CryptoUtil.generateAsymmetricKeyPair(RsaParameters.ALGORITHM_RSA);
		final String privKey = Base32Encoder.getInstance().encode(pair.getPrivate().getEncoded());
		final String publicKey = Base32Encoder.getInstance().encode(pair.getPrivate().getEncoded());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_CHARSET, cs.name());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, RsaParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, Base32Encoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_ENCRYPTION_KEY, privKey);
		properties.setProperty(ConfigurerUtil.KEY_DECRYPTION_KEY, publicKey);
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_CLASS, providerClass.getName());
		properties.setProperty(ConfigurerUtil.KEY_MAC_ALGORITHM, RsaParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.setProperty(ConfigurerUtil.KEY_MAC_KEY, macKey);
		properties.setProperty(ConfigurerUtil.KEY_PADDING, RsaParameters.PADDING_PKCS1);

		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(properties);
		final RsaParameters parameters = (RsaParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(privKey, parameters.getEncryptionKey());
		assertEquals(publicKey, parameters.getDecryptionKey());
		assertSame(providerClass, parameters.getProvider().getClass());
		assertEquals(RsaParameters.MAC_ALGORITHM_HMAC_SHA1, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(RsaParameters.PADDING_PKCS1, parameters.getPadding());
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
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY), "name");

		assertSame(encryptor, ConfigurerUtil.configureEncryptor(properties.getProperties(), propPrefix));

		properties.rollback();
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValuesViaSysProps1() throws Exception {
		final Charset cs = Charset.forName("UTF-8");
		final String key = Base32Encoder.getInstance().encode("SMOKESOMEOFMYTIE".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("SMOKEAJAYINTHEGOODOLUSA".getBytes());
		final String gcmSize = String.valueOf(CamelliaParameters.GCM_AUTH_TAG_LEN_128);
		final String propPrefix = "ejce.encryptor5";
		final VolatileProperties sysProps = new VolatileProperties(System.getProperties());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), Base64Encoder.class.getName());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), CamelliaParameters.class.getName());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ALGORITHM), CamelliaParameters.ALGORITHM_CAMELLIA);
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_CLASS), sun.security.provider.Sun.class.getName());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), CamelliaParameters.MAC_ALGORITHM_HMAC_MD5);
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), CamelliaParameters.BLOCK_MODE_GCM);
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), CamelliaParameters.PADDING_PKCS5);
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_GCM_TAG_LEN), gcmSize);

		final Properties props = new Properties();
		props.setProperty(ConfigurerUtil.KEY_PROPERTY_PREFIX, propPrefix);
		final Encryptor encryptor = ConfigurerUtil.configureEncryptor(props);
		final CamelliaParameters parameters = (CamelliaParameters) ReflectionUtil.getFieldValue(encryptor, "parameters");

		assertEquals(Base64Encoder.class, ReflectionUtil.getFieldValue(encryptor, "textEncoder").getClass());
		assertEquals(Base32Encoder.class, ReflectionUtil.getFieldValue(parameters, "textEncoder").getClass());
		assertEquals(cs, encryptor.getCharset());
		assertEquals(key, Base32Encoder.getInstance().encode(parameters.getKey().getEncoded()));
		assertEquals(CamelliaParameters.ALGORITHM_CAMELLIA, parameters.getAlgorithm());
		assertEquals(sun.security.provider.Sun.class, parameters.getProvider().getClass());
		assertEquals(CamelliaParameters.MAC_ALGORITHM_HMAC_MD5, parameters.getMacAlgorithm());
		assertEquals(macKey, Base32Encoder.getInstance().encode(parameters.getMacKey().getEncoded()));
		assertEquals(CamelliaParameters.BLOCK_MODE_GCM, parameters.getBlockMode());
		assertEquals(CamelliaParameters.GCM_AUTH_TAG_LEN_128, parameters.getGcmTagLen());
		assertEquals(CamelliaParameters.PADDING_PKCS5, parameters.getPadding());
		assertEquals(Integer.valueOf(gcmSize), (Integer)parameters.getGcmTagLen());

		sysProps.rollback();
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValuesViaSysProps2() throws Exception {
		final Charset cs = Charset.forName("UTF-16");
		final String key = Base32Encoder.getInstance().encode("SMOKESOMEOFMYTIE".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("SMOKEAJAYINTHEGOODOLUSA".getBytes());
		final String saltSize = "6";
		final String iterations = "700";
		final String propPrefix = "ejce.encryptor1";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), HexEncoder.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), PbeParameters.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ALGORITHM), PbeParameters.ALGORITHM_PBE_MD5_DES);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_CLASS), sun.security.provider.Sun.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), PbeParameters.MAC_ALGORITHM_HMAC_MD5);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), PbeParameters.BLOCK_MODE_OFB);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), PbeParameters.PADDING_PKCS5);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_SALT_SIZE), saltSize);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ITERATION_COUNT), iterations);

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

	@Test(expected = EncryptorConfigurationException.class)
	public void testSetParameterValuesViaSysPropsWrongProps() {
		final VolatileProperties sysProps = new VolatileProperties(System.getProperties());
		sysProps.setProperty(ConfigurerUtil.KEY_PROPERTY_PREFIX, "prefix");
		try {
			ConfigurerUtil.configureEncryptor(sysProps.getProperties());
		}
		finally {
			sysProps.rollback();
		}
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValues2ViaSysProps() throws Exception {

		final Charset cs = Charset.forName("ISO-8859-1");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final String propPrefix = "ejce.encryptor3";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), Base64UrlEncoder.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), BlowfishParameters.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_NAME), providerName);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), BlowfishParameters.BLOCK_MODE_OFB);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_SIZE), blockSize);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), BlowfishParameters.PADDING_NONE);

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
	 * @throws Exception Exception
	 */
	@Test
	public void testSetParameterValues3ViaSysProps() throws Exception {

		final Charset cs = Charset.forName("ISO-8859-1");
		final String key = Base32Encoder.getInstance().encode("BINGBINGA".getBytes());
		final String macKey = Base32Encoder.getInstance().encode("BEEOWANOWEEWEE".getBytes());
		final String providerName = "SunJCE";
		final String blockSize = "16";
		final String propPrefix = "ejce.encryptor2";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCODER_CLASS), Base64UrlEncoder.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CHARSET), cs.name());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_CLASS), BlowfishParameters.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PARAM_ENCODER_CLASS), Base32Encoder.class.getName());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_CIPHER_KEY), key);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PROVIDER_NAME), providerName);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_ALGORITHM), BlowfishParameters.MAC_ALGORITHM_HMAC_SHA1);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_MAC_KEY), macKey);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_MODE), BlowfishParameters.BLOCK_MODE_GCM);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_GCM_TAG_LEN), String.valueOf(BlowfishParameters.GCM_AUTH_TAG_LEN_112));
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_BLOCK_SIZE), blockSize);
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PADDING), BlowfishParameters.PADDING_NONE);

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
	 * @throws Exception Exception
	 */
	@Test(expected = EncryptorConfigurationException.class)
	public void testAsymetric() throws Exception {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, RsaParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_ALGORITHM, RsaParameters.ALGORITHM_RSA);

		ConfigurerUtil.loadAlgorithmParameters(properties, null);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadEncoder() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_ENCODER_CLASS, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadCharset() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_CHARSET, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesNoParams() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, "");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadParams1() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadParams2() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, Integer.class.getName());
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadParamEncoder() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PARAM_ENCODER_CLASS, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesNoKey() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadKeyLoader() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_KEY_LOADER, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesWrongKeyLoader() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_KEY_LOADER, Integer.class.getName());
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadProvider1() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, "MYSECRETKEY");
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_CLASS, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadProvider2() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, "MYSECRETKEY");
		properties.setProperty(ConfigurerUtil.KEY_PROVIDER_CLASS, Double.class.getName());
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadSaltGenerator1() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, "MYSECRETKEY");
		properties.setProperty(ConfigurerUtil.KEY_SALT_GENERATOR, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadSaltGenerator2() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, "MYSECRETKEY");
		properties.setProperty(ConfigurerUtil.KEY_SALT_GENERATOR, Integer.class.getName());
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadSaltMatcher1() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, "MYSECRETKEY");
		properties.setProperty(ConfigurerUtil.KEY_SALT_MATCHER, "o");
		ConfigurerUtil.configureEncryptor(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testParameterValuesBadSaltMatcher2() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PARAM_CLASS, TwofishParameters.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_CIPHER_KEY, "MYSECRETKEY");
		properties.setProperty(ConfigurerUtil.KEY_SALT_MATCHER, Integer.class.getName());
		ConfigurerUtil.configureEncryptor(properties);
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testPswdEncoderParameterValues() throws Exception {
		final String exportKey = "org.antfarmer.test.springPswdEncoder";
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PSWD_ENCODER_CLASS, SpringBcryptEncoder.class.getName());
		properties.setProperty(ConfigurerUtil.KEY_PSWD_ENCODER_STORE_EXPORT_KEY, exportKey);

		final ConfigurablePasswordEncoder encoder = ConfigurerUtil.configurePswdEncoder(properties);

		assertEquals(SpringBcryptEncoder.class, encoder.getClass());
		assertSame(encoder, PasswordEncoderStore.get(exportKey));
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testPswdEncoderViaStore() throws Exception {
		final String name = "name";
		final SpringBcryptEncoder pswdEnc = new SpringBcryptEncoder();
		PasswordEncoderStore.add(name, pswdEnc);

		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY, name);

		assertSame(pswdEnc, ConfigurerUtil.configurePswdEncoder(properties));

		// check missing encryptor from store
		PasswordEncoderStore.remove(name);
		Exception ex = null;
		try {
			ConfigurerUtil.configurePswdEncoder(properties);
		}
		catch (final Exception e) {
			ex = e;
		}
		assertEquals(EncryptorConfigurationException.class, ex.getClass());
	}

	/**
	 *
	 */
	@Test
	public void testPswdEncoderStoredViaSysProps() {
		final SpringBcryptEncoder pswdEnc = new SpringBcryptEncoder();
		PasswordEncoderStore.add("name", pswdEnc);

		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		final String propPrefix = "ejce.pswdEnc1";
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_ENCRYPTOR_STORE_KEY), "name");

		assertSame(pswdEnc, ConfigurerUtil.configurePswdEncoder(properties.getProperties(), propPrefix));

		properties.rollback();
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testPswdEncoderParameterValuesViaSysProps1() throws Exception {
		final String propPrefix = "ejce.pswdEnc1";
		final String exportKey = "org.antfarmer.test.springPswdEncoder";
		final VolatileProperties sysProps = new VolatileProperties(System.getProperties());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PSWD_ENCODER_CLASS), SpringBcryptEncoder.class.getName());
		sysProps.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PSWD_ENCODER_STORE_EXPORT_KEY), exportKey);

		final Properties props = new Properties();
		props.setProperty(ConfigurerUtil.KEY_PROPERTY_PREFIX, propPrefix);

		final ConfigurablePasswordEncoder encoder = ConfigurerUtil.configurePswdEncoder(props);

		assertEquals(SpringBcryptEncoder.class, encoder.getClass());
		assertSame(encoder, PasswordEncoderStore.get(exportKey));

		sysProps.rollback();
	}

	/**
	 * @throws Exception Exception
	 */
	@Test
	public void testPswdEncoderParameterValuesViaSysProps2() throws Exception {
		final String propPrefix = "ejce.pswdEnc1";
		final String exportKey = "org.antfarmer.test.springPswdEncoder";
		final VolatileProperties properties = new VolatileProperties(System.getProperties());
		properties.setProperty(getPropertyName(propPrefix, ConfigurerUtil.KEY_PSWD_ENCODER_CLASS), SpringBcryptEncoder.class.getName());

		final ConfigurablePasswordEncoder encoder = ConfigurerUtil.configurePswdEncoder(properties.getProperties(), propPrefix);

		assertEquals(SpringBcryptEncoder.class, encoder.getClass());
		assertNull(PasswordEncoderStore.get(exportKey));

		properties.rollback();
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testPswdEncoderParameterValuesViaSysPropsWrongProps() {
		final VolatileProperties sysProps = new VolatileProperties(System.getProperties());
		sysProps.setProperty(ConfigurerUtil.KEY_PROPERTY_PREFIX, "prefix");
		try {
			ConfigurerUtil.configurePswdEncoder(sysProps.getProperties());
		}
		finally {
			sysProps.rollback();
		}
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testPswdEncoderNoClass() {
		final Properties properties = new Properties();

		ConfigurerUtil.configurePswdEncoder(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testPswdEncoderBadClass() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PSWD_ENCODER_CLASS, "o");

		ConfigurerUtil.configurePswdEncoder(properties);
	}

	@Test(expected = EncryptorConfigurationException.class)
	public void testPswdEncoderWrongClass() {
		final Properties properties = new Properties();
		properties.setProperty(ConfigurerUtil.KEY_PSWD_ENCODER_CLASS, Integer.class.getName());

		ConfigurerUtil.configurePswdEncoder(properties);
	}

	@Test
	public void testGetCipherInstance() throws GeneralSecurityException {
		Cipher cipher;
		final AesParameters params = new AesParameters();
		cipher = ConfigurerUtil.getCipherInstance(params);
		assertEquals(AesParameters.ALGORITHM_AES + '/' + params.getBlockMode() + '/' + params.getPadding(), cipher.getAlgorithm());

		params.setBlockMode(AesParameters.BLOCK_MODE_CFB).setPadding(AesParameters.PADDING_PKCS5);
		cipher = ConfigurerUtil.getCipherInstance(params);
		assertEquals(AesParameters.ALGORITHM_AES + '/' + AesParameters.BLOCK_MODE_CFB + '/' + AesParameters.PADDING_PKCS5, cipher.getAlgorithm());

		params.setBlockMode(AesParameters.BLOCK_MODE_OFB).setPadding(AesParameters.PADDING_NONE).setProvider(new BouncyCastleProvider());
		cipher = ConfigurerUtil.getCipherInstance(params);
		assertEquals(AesParameters.ALGORITHM_AES + '/' + AesParameters.BLOCK_MODE_OFB + '/' + AesParameters.PADDING_NONE, cipher.getAlgorithm());
		assertEquals(BouncyCastleProvider.class, cipher.getProvider().getClass());
	}

	@Test
	public void testParseInt() {
		assertEquals(new Integer(1), ConfigurerUtil.parseInt("1"));
		assertEquals(new Integer(1), ConfigurerUtil.parseInt("01"));
		assertEquals(new Integer(10), ConfigurerUtil.parseInt("10"));
		assertEquals(new Integer(-10), ConfigurerUtil.parseInt("-10"));
		assertNull(ConfigurerUtil.parseInt("ddd"));
		assertNull(ConfigurerUtil.parseInt("d6d"));
		assertNull(ConfigurerUtil.parseInt(""));
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

	public static class MyKeyLoader implements KeyLoader {
		private static Key key;
		@Override
		public Key loadKey(final String algorithm) {
			try {
				return key = CryptoUtil.generateSecretKey(AbstractAlgorithmParameters.KEY_SIZE_128, algorithm);
			}
			catch (final NoSuchAlgorithmException e) {
				throw new EncryptorConfigurationException(e);
			}
		}
	}

	public static class MyMacKeyLoader implements KeyLoader {
		private static Key key;
		@Override
		public Key loadKey(final String algorithm) {
			try {
				return key = CryptoUtil.generateSecretKey(AbstractAlgorithmParameters.KEY_SIZE_128, algorithm);
			}
			catch (final NoSuchAlgorithmException e) {
				throw new EncryptorConfigurationException(e);
			}
		}
	}

}
