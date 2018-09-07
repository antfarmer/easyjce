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
 * Utility related to Java environment.
 * @author Ameer Antar
 */
public class EnvironmentUtil {

	public static final double JAVA_VERSION = getVersion();

	private EnvironmentUtil() {
		// static only
	}

	private static final double getVersion() {
		final String ver = System.getProperty("java.version").trim();
		return Double.parseDouble(ver.replaceAll("^(\\d+\\.\\d+).*$", "$1"));
	}
}
