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
package org.antfarmer.ejce.parameter.key_loader;

import java.security.Key;

import org.antfarmer.ejce.util.CryptoUtil;

/**
 * Abstract implementation of a <code>KeyLoader</code> for symmetric ciphers.
 * @author Ameer Antar
 */
public abstract class AbstractSymmetricKeyLoader implements KeyLoader {

	/**
	 * {@inheritDoc}
	 */
	public Key loadKey(final String algorithm) {
		return CryptoUtil.getSecretKeyFromRawKey(loadRawKey(), algorithm);
	}

	/**
	 * Loads a cipher key in its raw byte form.
	 * @return a cipher key
	 */
	protected abstract byte[] loadRawKey();
}
