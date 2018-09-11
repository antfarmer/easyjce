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
package org.antfarmer.ejce;

import java.nio.charset.Charset;

import org.antfarmer.ejce.encoder.TextEncoder;

/**
 * Main concrete class which can encrypt/decrypt any type of object. <b>This class is thread-safe.</b>
 * <br><br>
 * Here's a simple example for encrypting a string.
 *
 * <pre>
 *	PbeParameters parameters = new PbeParameters()
 *		.setKey(<font color="#0033CC">"key12345678909876543210"</font>)
 *		<font color="#008822">// the MAC settings are optional, but will ensure that the message
 *		// was not altered during transmission.</font>
 *		.setMacAlgorithm(DesEdeParameters.MAC_ALGORITHM_HMAC_SHA1)
 *		.setMacKey(<font color="#0033CC">"12345678"</font>)
 *		;
 *	Encryptor encryptor = new Encryptor(Base64Encoder.<i>getInstance</i>())
 *		.setAlgorithmParameters(parameters);
 *	Encryptor decryptor = new Encryptor(Base64Encoder.<i>getInstance</i>())
 *		.setAlgorithmParameters(parameters);
 *
 *	encryptor.initialize();
 *	decryptor.initialize();
 *
 *	String plainText = <font color="#0033CC">"abcdefghijklmnopqrstuvwxyz"</font>;
 *	String enc = encryptor.encrypt(plainText);
 *	System.out.println(enc);
 *	System.out.println(decryptor.decrypt(enc));
 *	enc = encryptor.encrypt(plainText);
 *	System.out.println(enc);
 *	System.out.println(decryptor.decrypt(enc));
 *	enc = decryptor.encrypt(plainText);
 *	System.out.println(enc);
 *	System.out.println(encryptor.decrypt(enc));
 *  </pre>
 *
 *  Of course, you only need one object to encrypt and decrypt (each Encryptor has
 *  separate cipher instances for encryption and decrytion), but this example shows
 *  that two instances, which produce different encryption results, can decrypt the
 *  other's encrypted message, so long as they share the secret-key.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class Encryptor extends AbstractValueEncryptor<Encryptor> {

	/**
	 * Initializes the Encryptor with a {@link org.antfarmer.ejce.encoder.HexEncoder} used for
	 * encoding/decoding byte arrays. Uses the default {@link Charset} for UTF-8.
	 */
	public Encryptor() {
		super();
	}

	/**
	 * Initializes the Encryptor with the given {@link org.antfarmer.ejce.encoder.TextEncoder} used
	 * for encoding/decoding byte arrays. Uses the default {@link Charset} for UTF-8.
	 *
	 * @param textEncoder the {@link org.antfarmer.ejce.encoder.TextEncoder} used for
	 *        encoding/decoding byte arrays
	 */
	public Encryptor(final TextEncoder textEncoder) {
		super(textEncoder);
	}

	/**
	 * Initializes the Encryptor with the given {@link org.antfarmer.ejce.encoder.TextEncoder} and
	 * {@link Charset} used for encoding/decoding byte arrays.
	 *
	 * @param textEncoder the {@link org.antfarmer.ejce.encoder.TextEncoder} used for
	 *        encoding/decoding byte arrays
	 * @param charset the {@link Charset} used used for encoding/decoding byte arrays
	 */
	public Encryptor(final TextEncoder textEncoder, final Charset charset) {
		super(textEncoder, charset);
	}

}
