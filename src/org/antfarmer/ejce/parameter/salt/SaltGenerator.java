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
package org.antfarmer.ejce.parameter.salt;

/**
 * Interface which allows custom salt generation used during the encryption process.
 * @author Ameer Antar
 */
public interface SaltGenerator {

	/**
	 * Callback used to populate the salt data for the encryption process. The salt data should be filled into the
	 * supplied <code>saltData</code> byte array.
	 * @param saltData the byte array to be populated with salt data
	 */
	void generateSalt(byte[] saltData);
}
