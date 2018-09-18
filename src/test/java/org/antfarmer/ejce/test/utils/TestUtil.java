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
package org.antfarmer.ejce.test.utils;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * Test utilities.
 * @author Ameer Antar
 */
public class TestUtil {

	/**
	 * Returns the generic type on the given class.
	 * @param inspectClass the class to inspect
	 * @param genericType the generic superclass expected to be found
	 * @return the generic type on the given class
	 */
	@SuppressWarnings("unchecked")
	public static <T> Class<T> getGenericType(final Class<?> inspectClass, final Class<?> genericType) {
		Class<?> clazz = inspectClass;
		Type type = clazz.getGenericSuperclass();
		while (true) {
			if (type instanceof ParameterizedType) {
				final Type[] arguments = ((ParameterizedType)type).getActualTypeArguments();
				for (final Type argument : arguments) {
					if (argument instanceof Class && genericType.isAssignableFrom((Class<?>)argument)) {
						return (Class<T>)argument;
					}
				}
				clazz = clazz.getSuperclass();
				type = clazz.getGenericSuperclass();
			}
			else {
				type = ((Class<?>)type).getGenericSuperclass();
			}
			if (type == Object.class) {
				throw new RuntimeException("Could not find a " + genericType.getName()
					+ " subclass parameterized type on: " + inspectClass.getName());
			}
		}
	}

}
