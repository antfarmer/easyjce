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
package org.antfarmer.ejce.encoder;

/**
 * Interface for encoding/decoding bytes and text.
 * 
 * @author Ameer Antar
 * @version 1.0
 */
public interface TextEncoder {

	/**
	 * Encodes the byte array to a string.
	 * 
	 * @param bytes the byte array
	 * @return a string representation of the byte array
	 */
	String encode(byte[] bytes);

	/**
	 * Decodes the string into a byte array.
	 * 
	 * @param text the encoded text
	 * @return the byte array represented by the encoded text
	 */
	byte[] decode(String text);
}
