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
package org.antfarmer.ejce.test.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * A wrapper for the {@link Properties} class which tracks all additions to the properties, so that they can be rolled
 * back later.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class VolatileProperties {

	private static final long serialVersionUID = -1271362966142011021L;

	private final Properties properties;

	private final List<Object> propKeys;

	/**
	 * Initializes the VolatileProperties.
	 *
	 * @param properties the properties
	 */
	public VolatileProperties(final Properties properties) {
		this.properties = properties;
		propKeys = new ArrayList<Object>();
	}

	/**
	 * Maps the specified key to the specified value in this hashtable. Neither the key nor the value can be null. The
	 * value can be retrieved by calling the get method with a key that is equal to the original key.
	 *
	 * @param key the hashtable key
	 * @param value the value
	 * @return the previous value of the specified key in this hashtable, or null if it did not have one
	 * @see java.util.Hashtable#put(java.lang.Object, java.lang.Object)
	 */
	public Object put(final Object key, final Object value) {
		propKeys.add(key);
		return properties.put(key, value);
	}

	/**
	 * Copies all of the mappings from the specified Map to this Hashtable These mappings will replace any mappings that
	 * this Hashtable had for any of the keys currently in the specified Map.
	 *
	 * @param t Mappings to be stored in this map
	 * @see java.util.Hashtable#putAll(java.util.Map)
	 */
	public void putAll(final Map<? extends Object, ? extends Object> t) {
		propKeys.addAll(t.keySet());
		properties.putAll(t);
	}

	/**
	 * Calls the Hashtable method put. Provided for parallelism with the getProperty method. Enforces use of strings for
	 * property keys and values. The value returned is the result of the Hashtable call to put.
	 *
	 * @param key the key to be placed into this property list
	 * @param value the value corresponding to key
	 * @return the previous value of the specified key in this property list, or null if it did not have one
	 * @see java.util.Properties#setProperty(java.lang.String, java.lang.String)
	 */
	public Object setProperty(final String key, final String value) {
		propKeys.add(key);
		return properties.setProperty(key, value);
	}

	/**
	 * Rolls back all additions made to the properties through this class.
	 */
	public void rollback() {
		for (final Object key : propKeys) {
			properties.remove(key);
		}
	}

	/**
	 * Returns the properties value.
	 *
	 * @return the properties.
	 */
	public Properties getProperties() {
		return properties;
	}
}
