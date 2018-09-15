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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Provides in-memory storage for encryptors, allowing shared access for application code as well as
 * Hibernate user types. In order for the encryptors to be available to the Hibernate user types,
 * the encryptors must be loaded into the store before the Hibernate mappings are added to the
 * session factory configuration.
 *
 * @author Ameer Antar
 * @version 1.1
 */
public class EncryptorStore {

	private static final Map<String, Encryptor> store = new HashMap<String, Encryptor>();
	private static final ReentrantLock lock = new ReentrantLock();

	private EncryptorStore() {
		// static methods only
	}

	/**
	 * Adds the given {@link Encryptor} for the given name.
	 *
	 * @param key the unique key to identify the {@link Encryptor}
	 * @param encryptor the {@link Encryptor} to be stored
	 * @return the {@link Encryptor}
	 */
	public static Encryptor add(final String key, final Encryptor encryptor) {
		lock.lock();
		try {
			return store.put(key, encryptor);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the {@link Encryptor} for the given name.
	 *
	 * @param key the unique key of the {@link Encryptor}
	 * @return the {@link Encryptor} for the given name
	 */
	public static Encryptor get(final String key) {
		lock.lock();
		try {
			return store.get(key);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Removes the {@link Encryptor} with the given name.
	 *
	 * @param key the unique key of the {@link Encryptor}
	 * @return the removed {@link Encryptor}
	 */
	public static Encryptor remove(final String key) {
		lock.lock();
		try {
			return store.remove(key);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Removes all {@link Encryptor}'s from the store.
	 */
	public static void clear() {
		lock.lock();
		try {
			store.clear();;
		}
		finally {
			lock.unlock();
		}
	}

}
