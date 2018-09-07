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
 * Abstract class for Argon2 password encoder implementations.
 *
 * @author Ameer Antar
 */
public abstract class AbstractArgon2PasswordEncoder extends AbstractConfigurablePasswordEncoder {

	/**
	 * Property key for the algorithm type to use, d, i, or id. Default is id.
	 */
	public static final String KEY_TYPE = "type";

	/**
	 * Property key for the hash length in bytes for the algorithm. The default is currently 32.
	 */
	public static final String KEY_HASH_LENGTH = "hashLen";

	/**
	 * Property key for the salt length in bytes. The default is currently 16.
	 */
	public static final String KEY_SALT_LENGTH = "saltLen";

	/**
	 * Property key for the number of iterations. The default is currently 50.
	 */
	public static final String KEY_ITERATIONS = "iterations";

	/**
	 * Property key for the memory size in KB. The default is currently 4096 KB.
	 */
	public static final String KEY_MEMORY_SIZE = "memSize";

	/**
	 * Property key for the degree of parallelism (thread count). The default is currently 2.
	 */
	public static final String KEY_PARALLELISM = "parallelism";

	/**
	 * The 'd' type (maximizes resistance to GPU cracking attacks).
	 */
	public static final String TYPE_D = "d";

	/**
	 * The 'i' type (optimized to resist side-channel attacks).
	 */
	public static final String TYPE_I = "i";

	/**
	 * The 'id' type (a hybrid version).
	 */
	public static final String TYPE_ID = "id";

	/**
	 * The default algorithm type 'id', if no value is specified.
	 */
	public static final String DEFAULT_TYPE = TYPE_ID;

	/**
	 * The default hash length in bytes if no value is specified.
	 */
	public static final int DEFAULT_HASH_LENGTH = 32;

	/**
	 * The default salt length in bytes if no value is specified.
	 */
	public static final int DEFAULT_SALT_LENGTH = 16;

	/**
	 * The default number of iterations if no value is specified.
	 */
	public static final int DEFAULT_ITERATIONS = 50;

	/**
	 * The default memory size if no value is specified.
	 */
	public static final int DEFAULT_MEMORY_SIZE = 4096;

	/**
	 * The default degree of parallelism if no value is specified.
	 */
	public static final int DEFAULT_PARALLELISM = 2;

}
