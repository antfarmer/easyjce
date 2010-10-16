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
package org.antfarmer.ejce;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;

import org.antfarmer.ejce.encoder.HexEncoder;
import org.antfarmer.ejce.encoder.TextEncoder;
import org.antfarmer.ejce.util.ByteUtil;

/**
 * Abstract class for encrypting/decrypting text and other values.
 *
 * @author Ameer Antar
 * @version 1.2
 * @param <T> the concrete type of this encryptor object.
 */
public abstract class AbstractValueEncryptor<T extends AbstractValueEncryptor<T>>
		extends AbstractEncryptor<T> implements ValueEncryptorInterface<T> {

	private final TextEncoder textEncoder;

	/**
	 * Initializes the AbstractValueEncryptor with a {@link HexEncoder} used for encoding/decoding byte
	 * arrays.
	 */
	public AbstractValueEncryptor() {
		this.textEncoder = HexEncoder.getInstance();
	}

	/**
	 * Initializes the AbstractValueEncryptor with the given {@link TextEncoder} used for
	 * encoding/decoding byte arrays.
	 *
	 * @param textEncoder the {@link TextEncoder} used for encoding/decoding byte arrays
	 */
	public AbstractValueEncryptor(final TextEncoder textEncoder) {
		this.textEncoder = textEncoder;
	}

	/**
	 * {@inheritDoc}
	 */
	public String encrypt(final String text) throws GeneralSecurityException {
		return encrypt(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String decrypt(final String text) throws GeneralSecurityException {
		return decrypt(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptAndEncode(final byte[] bytes) throws GeneralSecurityException {
		return encryptAndEncode(bytes, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] decryptAndDecode(final String text) throws GeneralSecurityException {
		return decryptAndDecode(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptCharacter(final Character number)
			throws GeneralSecurityException {
		return encryptCharacter(number, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Character decryptCharacter(final String text)
			throws GeneralSecurityException {
		return decryptCharacter(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptLong(final Long number) throws GeneralSecurityException {
		return encryptLong(number, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Long decryptLong(final String text) throws GeneralSecurityException {
		return decryptLong(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptInteger(final Integer number)
			throws GeneralSecurityException {
		return encryptInteger(number, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Integer decryptInteger(final String text) throws GeneralSecurityException {
		return decryptInteger(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptShort(final Short number) throws GeneralSecurityException {
		return encryptShort(number, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Short decryptShort(final String text) throws GeneralSecurityException {
		return decryptShort(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptBoolean(final Boolean value)
			throws GeneralSecurityException {
		return encryptBoolean(value, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Boolean decryptBoolean(final String text) throws GeneralSecurityException {
		return decryptBoolean(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptDouble(final Double number) throws GeneralSecurityException {
		return encryptDouble(number, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Double decryptDouble(final String text) throws GeneralSecurityException {
		return decryptDouble(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptFloat(final Float number) throws GeneralSecurityException {
		return encryptFloat(number, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Float decryptFloat(final String text) throws GeneralSecurityException {
		return decryptFloat(text, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptObject(final Object object)
			throws GeneralSecurityException, IOException {
		return encryptObject(object, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public Object decryptObject(final String text)
			throws GeneralSecurityException, IOException, ClassNotFoundException {
		return decryptObject(text, null);
	}

	/* Specified keys *******************************************************************/

	/**
	 * {@inheritDoc}
	 */
	public String encrypt(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return textEncoder.encode(encrypt(text.getBytes(), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String decrypt(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return new String(decrypt(textEncoder.decode(text), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptAndEncode(final byte[] bytes, final Key key) throws GeneralSecurityException {
		if (bytes == null) {
			return null;
		}
		return textEncoder.encode(encrypt(bytes, key));
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] decryptAndDecode(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return decrypt(textEncoder.decode(text), key);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptCharacter(final Character number, final Key key)
			throws GeneralSecurityException {
		if (number == null) {
			return null;
		}
		return textEncoder.encode(encrypt(String.valueOf(number).getBytes(), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Character decryptCharacter(final String text, final Key key)
			throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return new String(decrypt(textEncoder.decode(text), key)).charAt(0);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptLong(final Long number, final Key key) throws GeneralSecurityException {
		if (number == null) {
			return null;
		}
		return textEncoder.encode(encrypt(ByteUtil.toBytes(number), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Long decryptLong(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return ByteUtil.toLong(decrypt(textEncoder.decode(text), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptInteger(final Integer number, final Key key)
			throws GeneralSecurityException {
		if (number == null) {
			return null;
		}
		return textEncoder.encode(encrypt(ByteUtil.toBytes(number), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Integer decryptInteger(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return ByteUtil.toInt(decrypt(textEncoder.decode(text), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptShort(final Short number, final Key key) throws GeneralSecurityException {
		if (number == null) {
			return null;
		}
		return textEncoder.encode(encrypt(ByteUtil.toBytes(number), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Short decryptShort(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return ByteUtil.toShort(decrypt(textEncoder.decode(text), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptBoolean(final Boolean value, final Key key)
			throws GeneralSecurityException {
		if (value == null) {
			return null;
		}
		return textEncoder.encode(encrypt(new byte[] {(byte) (value ? 1 : 0)}, key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Boolean decryptBoolean(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return decrypt(textEncoder.decode(text), key)[0] == 1 ? true : false;
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptDouble(final Double number, final Key key) throws GeneralSecurityException {
		if (number == null) {
			return null;
		}
		return textEncoder.encode(encrypt(ByteUtil.toBytes(number), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Double decryptDouble(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return ByteUtil.toDouble(decrypt(textEncoder.decode(text), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptFloat(final Float number, final Key key) throws GeneralSecurityException {
		if (number == null) {
			return null;
		}
		return textEncoder.encode(encrypt(ByteUtil.toBytes(number), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Float decryptFloat(final String text, final Key key) throws GeneralSecurityException {
		if (text == null) {
			return null;
		}
		return ByteUtil.toFloat(decrypt(textEncoder.decode(text), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public String encryptObject(final Object object, final Key key)
			throws GeneralSecurityException, IOException {
		if (object == null) {
			return null;
		}
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = null;
		try {
			oos = new ObjectOutputStream(baos);
			oos.writeObject(object);
		}
		catch (final IOException e) {
			throw e;
		}
		finally {
			closeStream(oos);
		}
		return textEncoder.encode(encrypt(baos.toByteArray(), key));
	}

	/**
	 * {@inheritDoc}
	 */
	public Object decryptObject(final String text, final Key key)
			throws GeneralSecurityException, IOException, ClassNotFoundException {
		if (text == null) {
			return null;
		}
		Object object;
		final ByteArrayInputStream bais = new ByteArrayInputStream(decrypt(textEncoder.decode(text), key));
		ObjectInputStream ois = null;
		try {
			ois = new ObjectInputStream(bais);
			object = ois.readObject();
		}
		catch (final IOException e) {
			throw e;
		}
		finally {
			closeStream(ois);
		}
		return object;
	}



	private void closeStream(final Closeable stream) {
		if (stream != null) {
			try {
				stream.close();
			}
			catch (final IOException e) {
				// ignore
			}
		}
	}

}
