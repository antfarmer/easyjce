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
 * Abstract class for BCrypt password encoder implementations.
 *
 * @author Ameer Antar
 */
public abstract class AbstractBcryptPasswordEncoder extends AbstractConfigurablePasswordEncoder {

	/**
	 * Property key for the log rounds to use, between 4 and 31. Default is 12.
	 */
	public static final String KEY_STRENGTH = "strength";

	/**
	 * The default strength if no value is specified.
	 */
	public static final int DEFAULT_STRENGTH = 12;

}
