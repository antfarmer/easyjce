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
 * Abstract class for SCrypt password encoder implementations.
 *
 * @author Ameer Antar
 */
public abstract class AbstractScryptPasswordEncoder extends AbstractConfigurablePasswordEncoder {

	/**
	 * Property key for the cpu cost of the algorithm (as defined in scrypt this is N). Must be power of
	 * 2 greater than 1. Default is currently 16,348 or 2^14
	 */
	public static final String KEY_CPU_COST = "cpu";

	/**
	 * Property key for the memory cost of the algorithm (as defined in scrypt this is r). Default is
	 * currently 8.
	 */
	public static final String KEY_MEM_COST = "mem";

	/**
	 * Property key for the parallelization of the algorithm (as defined in scrypt this is p) Default is
	 * currently 1. Note that the implementation does not currently take advantage of parallelization.
	 */
	public static final String KEY_PARALLELIZATION = "parallelization";

	/**
	 * Property key for the key length in bytes for the algorithm (as defined in scrypt this is dkLen).
	 * The default is currently 32.
	 */
	public static final String KEY_KEY_LENGTH = "keyLen";

	/**
	 * Property key for the salt length in bytes (as defined in scrypt this is the length of S). The
	 * default is currently 64.
	 */
	public static final String KEY_SALT_LENGTH = "saltLen";

	/**
	 * The default CPU cost if no value is specified.
	 */
	public static final int DEFAULT_CPU_COST = 16384;

	/**
	 * The default Memory cost if no value is specified.
	 */
	public static final int DEFAULT_MEM_COST = 8;

	/**
	 * The default Parallelization value if no value is specified.
	 */
	public static final int DEFAULT_PARALLELIZATION = 1;

	/**
	 * The default key length in bytes if no value is specified.
	 */
	public static final int DEFAULT_KEY_LENGTH = 32;

	/**
	 * The default salt length in bytes if no value is specified.
	 */
	public static final int DEFAULT_SALT_LENGTH = 64;

}
