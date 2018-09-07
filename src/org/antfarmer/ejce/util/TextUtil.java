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
package org.antfarmer.ejce.util;

/**
 * Text-related utilities.
 * @author Ameer Antar
 */
public class TextUtil {

	private TextUtil() {
		// static only
	}

	/**
	 * Determines if the given text is not null and has length.
	 * @param text the text
	 * @return true if the given text is not null and has length
	 */
	public static boolean hasLength(final String text) {
		return !(text == null || text.length() < 1);
	}

}
