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
package org.antfarmer.ejce.password.encoder;

import org.antfarmer.ejce.password.AbstractConfigurablePasswordEncoder;

/**
 * Abstract class for PBKDF2 password encoder implementations.
 *
 * @author Ameer Antar
 */
public abstract class AbstractPbkdf2PasswordEncoder extends AbstractConfigurablePasswordEncoder {

	/**
	 * Property key for the secret value which is also included in the password hash. Default is none.
	 */
	public static final String KEY_SECRET = "secret";

	/**
	 * Property key for the hash length in bits for the algorithm. The default is currently 512.
	 */
	public static final String KEY_HASH_LENGTH = "hashLen";

	/**
	 * Property key for the number of iterations. Users should aim for taking about .5 seconds on their
	 * own system. The default is currently 185000.
	 */
	public static final String KEY_ITERATIONS = "iterations";

	/**
	 * Property key for the name algorithm to use. The default is currently PBKDF2withHmacSHA1 or
	 * PBKDF2withHmacSHA512 [JRE &gt;= 1.8].
	 */
	public static final String KEY_ALGORITHM = "algorithm";

	/**
	 * The default hash length in bits if no value is specified.
	 */
	public static final int DEFAULT_HASH_LENGTH = 512;

	/**
	 * The default number of iterations if no value is specified.
	 */
	public static final int DEFAULT_ITERATIONS = 185000;

}
