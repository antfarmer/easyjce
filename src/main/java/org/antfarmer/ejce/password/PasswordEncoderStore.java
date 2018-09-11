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
package org.antfarmer.ejce.password;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Provides in-memory storage for password encoders, allowing shared access for application code
 * as well as Hibernate user types. In order for the password encoders to be available to the
 * Hibernate user types, the password encoders must be loaded into the store before the Hibernate
 * mappings are added to the session factory configuration.
 *
 * @author Ameer Antar
 * @version 1.1
 */
public class PasswordEncoderStore {

	private static final Map<String, ConfigurablePasswordEncoder> store = new HashMap<String, ConfigurablePasswordEncoder>();
	private static final ReentrantLock lock = new ReentrantLock();

	private PasswordEncoderStore() {
		// static methods only
	}

	/**
	 * Adds the given {@link ConfigurablePasswordEncoder} for the given name.
	 *
	 * @param key the unique key to identify the {@link ConfigurablePasswordEncoder}
	 * @param encryptor the {@link ConfigurablePasswordEncoder} to be stored
	 * @return the {@link ConfigurablePasswordEncoder}
	 */
	public static ConfigurablePasswordEncoder add(final String key, final ConfigurablePasswordEncoder encryptor) {
		lock.lock();
		try {
			return store.put(key, encryptor);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the {@link ConfigurablePasswordEncoder} for the given name.
	 *
	 * @param key the unique key of the {@link ConfigurablePasswordEncoder}
	 * @return the {@link ConfigurablePasswordEncoder} for the given name
	 */
	public static ConfigurablePasswordEncoder get(final String key) {
		lock.lock();
		try {
			return store.get(key);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Removes the {@link ConfigurablePasswordEncoder} with the given name.
	 *
	 * @param key the unique key of the {@link ConfigurablePasswordEncoder}
	 * @return the removed {@link ConfigurablePasswordEncoder}
	 */
	public static ConfigurablePasswordEncoder remove(final String key) {
		lock.lock();
		try {
			return store.remove(key);
		}
		finally {
			lock.unlock();
		}
	}

}
