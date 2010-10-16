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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 * Interface for encrypting/decrypting text and other values.
 * @author Ameer Antar
 * @version 1.0
 * @param <T> the concrete type of this Encryptor object.
 */
public interface ValueEncryptorInterface<T extends ValueEncryptorInterface<T>> extends EncryptorInterface<T> {

	/**
	 * Returns an encrypted and encoded text representation of the given text.
	 * @param text the text to be encrypted
	 * @return an encrypted and encoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encrypt(String text) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted text for the given text representation. This method will only work with data
	 * encrypted using the <code>encrypt</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String decrypt(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given bytes.
	 * @param bytes the bytes to be encrypted
	 * @return an encrypted and encoded version of the bytes
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptAndEncode(byte[] bytes) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted bytes for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptAndEncode</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	byte[] decryptAndDecode(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given boolean. This is generally the most efficient
	 * means of encrypting a boolean, as the bit representation is used for encryption rather than the string
	 * representation.
	 * @param value the short to be encrypted
	 * @return an encrypted and encoded version of the boolean
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptBoolean(Boolean value) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted boolean for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptBoolean</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Boolean decryptBoolean(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given character.
	 * @param number the character to be encrypted
	 * @return an encrypted and encoded version of the character
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptCharacter(Character number) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted character for the given text representation. This method will only work with
	 * data encrypted using the <code>encryptCharacter</code> method.
	 * @param text the character to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Character decryptCharacter(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given double. This is generally the most efficient
	 * means of encrypting a double, as the byte representation is used for encryption rather than the string
	 * representation.
	 * @param number the double to be encrypted
	 * @return an encrypted and encoded version of the double
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptDouble(Double number) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted double for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptDouble</code> method.
	 * @param text the double to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Double decryptDouble(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given float. This is generally the most efficient
	 * means of encrypting a float, as the byte representation is used for encryption rather than the string
	 * representation.
	 * @param number the float to be encrypted
	 * @return an encrypted and encoded version of the float
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptFloat(Float number) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted float for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptFloat</code> method.
	 * @param text the float to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Float decryptFloat(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given integer. This is generally the most efficient
	 * means of encrypting an integer, as the byte representation is used for encryption rather than the string
	 * representation.
	 * @param number the integer to be encrypted
	 * @return an encrypted and encoded version of the integer
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptInteger(Integer number) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted integer for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptInteger</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the integer
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Integer decryptInteger(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given long. This is generally the most efficient
	 * means of encrypting a long, as the byte representation is used for encryption rather than the string
	 * representation.
	 * @param number the long to be encrypted
	 * @return an encrypted and encoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptLong(Long number) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted long for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptLong</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Long decryptLong(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given object. The object should implement
	 * {@link java.io.Serializable}.
	 * @param object the object to be encrypted
	 * @return an encrypted and encoded version of the object
	 * @throws GeneralSecurityException GeneralSecurityException
	 * @throws IOException IOException
	 */
	String encryptObject(Object object) throws GeneralSecurityException, IOException;

	/**
	 * Returns the decoded and decrypted object for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptObject</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the object
	 * @throws GeneralSecurityException GeneralSecurityException
	 * @throws IOException IOException
	 * @throws ClassNotFoundException ClassNotFoundException
	 */
	Object decryptObject(String text) throws GeneralSecurityException, IOException, ClassNotFoundException;

	/**
	 * Returns an encrypted and encoded text representation of the given short. This is generally the most efficient
	 * means of encrypting a short, as the byte representation is used for encryption rather than the string
	 * representation.
	 * @param number the short to be encrypted
	 * @return an encrypted and encoded version of the short
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptShort(Short number) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted short for the given text representation. This method will only work with data
	 * encrypted using the <code>encryptShort</code> method.
	 * @param text the text to be decrypted
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Short decryptShort(String text) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given text, using the given <code>Key</code>.
	 * @param text the text to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encrypt(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted text for the given text representation, using the given <code>Key</code>. This
	 * method will only work with data encrypted using the <code>encrypt</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String decrypt(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given bytes, using the given <code>Key</code>.
	 * @param bytes the bytes to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the bytes
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptAndEncode(byte[] bytes, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted bytes for the given text representation, using the given <code>Key</code>. This
	 * method will only work with data encrypted using the <code>encryptAndEncode</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	byte[] decryptAndDecode(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given boolean, using the given <code>Key</code>. This
	 * is generally the most efficient means of encrypting a boolean, as the bit representation is used for encryption
	 * rather than the string representation.
	 * @param value the short to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the boolean
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptBoolean(Boolean value, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted boolean for the given text representation, using the given <code>Key</code>.
	 * This method will only work with data encrypted using the <code>encryptBoolean</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Boolean decryptBoolean(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given character, using the given <code>Key</code>.
	 * @param number the character to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the character
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptCharacter(Character number, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted character for the given text representation, using the given <code>Key</code>.
	 * This method will only work with data encrypted using the <code>encryptCharacter</code> method.
	 * @param text the character to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Character decryptCharacter(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given double, using the given <code>Key</code>. This
	 * is generally the most efficient means of encrypting a double, as the byte representation is used for encryption
	 * rather than the string representation.
	 * @param number the double to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the double
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptDouble(Double number, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted double for the given text representation, using the given <code>Key</code>.
	 * This method will only work with data encrypted using the <code>encryptDouble</code> method.
	 * @param text the double to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Double decryptDouble(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given float, using the given <code>Key</code>. This
	 * is generally the most efficient means of encrypting a float, as the byte representation is used for encryption
	 * rather than the string representation.
	 * @param number the float to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the float
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptFloat(Float number, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted float for the given text representation, using the given <code>Key</code>. This
	 * method will only work with data encrypted using the <code>encryptFloat</code> method.
	 * @param text the float to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Float decryptFloat(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given integer, using the given <code>Key</code>. This
	 * is generally the most efficient means of encrypting an integer, as the byte representation is used for encryption
	 * rather than the string representation.
	 * @param number the integer to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the integer
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptInteger(Integer number, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted integer for the given text representation, using the given <code>Key</code>.
	 * This method will only work with data encrypted using the <code>encryptInteger</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the integer
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Integer decryptInteger(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given long, using the given <code>Key</code>. This is
	 * generally the most efficient means of encrypting a long, as the byte representation is used for encryption rather
	 * than the string representation.
	 * @param number the long to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptLong(Long number, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted long for the given text representation, using the given <code>Key</code>. This
	 * method will only work with data encrypted using the <code>encryptLong</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Long decryptLong(String text, Key key) throws GeneralSecurityException;

	/**
	 * Returns an encrypted and encoded text representation of the given object, using the given <code>Key</code>. The
	 * object should implement {@link java.io.Serializable}.
	 * @param object the object to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the object
	 * @throws GeneralSecurityException GeneralSecurityException
	 * @throws IOException IOException
	 */
	String encryptObject(Object object, Key key) throws GeneralSecurityException, IOException;

	/**
	 * Returns the decoded and decrypted object for the given text representation, using the given <code>Key</code>.
	 * This method will only work with data encrypted using the <code>encryptObject</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the object
	 * @throws GeneralSecurityException GeneralSecurityException
	 * @throws IOException IOException
	 * @throws ClassNotFoundException ClassNotFoundException
	 */
	Object decryptObject(String text, Key key) throws GeneralSecurityException, IOException,
			ClassNotFoundException;

	/**
	 * Returns an encrypted and encoded text representation of the given short, using the given <code>Key</code>. This
	 * is generally the most efficient means of encrypting a short, as the byte representation is used for encryption
	 * rather than the string representation.
	 * @param number the short to be encrypted
	 * @param key the encryption key
	 * @return an encrypted and encoded version of the short
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	String encryptShort(Short number, Key key) throws GeneralSecurityException;

	/**
	 * Returns the decoded and decrypted short for the given text representation, using the given <code>Key</code>. This
	 * method will only work with data encrypted using the <code>encryptShort</code> method.
	 * @param text the text to be decrypted
	 * @param key the decryption key
	 * @return a decrypted and decoded version of the text
	 * @throws GeneralSecurityException GeneralSecurityException
	 */
	Short decryptShort(String text, Key key) throws GeneralSecurityException;
}
