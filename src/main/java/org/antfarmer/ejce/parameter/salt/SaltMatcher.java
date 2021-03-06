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
package org.antfarmer.ejce.parameter.salt;

import java.security.GeneralSecurityException;

/**
 * Interface which allows for matching an expected salt byte array during the decryption process.
 * @author Ameer Antar
 */
public interface SaltMatcher {

	/**
	 * Callback used to match the expected salt byte array with the one found in the enciphered message during
	 * decryption. If the expected and actual data do not match, a <code>GeneralSecurityException</code> may be thrown
	 * to prevent the decryption process.
	 * @param cipherSalt the actual salt data found in the enciphered message
	 * @throws GeneralSecurityException if the expected and actual salt data do not match
	 */
	void verifySaltMatch(byte[] cipherSalt) throws GeneralSecurityException;
}
