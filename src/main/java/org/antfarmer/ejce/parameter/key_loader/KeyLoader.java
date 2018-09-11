/*
 * Copyright 2008 the original author or authors.
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

/**
 * Interface for loading cipher keys from various sources.
 * @author Ameer Antar
 * @version 1.0
 */
public interface KeyLoader {

	/**
	 * Loads a cipher key.
	 * @param algorithm the algorithm for the key
	 * @return a cipher key
	 */
	Key loadKey(String algorithm);
}
