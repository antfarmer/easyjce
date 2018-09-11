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
package org.antfarmer.ejce.util;

import java.lang.reflect.Field;

/**
 * Provides reflection utility methods.
 *
 * @author Ameer Antar
 * @version 1.0
 */
public final class ReflectionUtil {

	private ReflectionUtil() {
		// static methods only
	}

	/**
	 * Sets the given object's field to the given value.
	 *
	 * @param object the object whose field value will be set
	 * @param value the value which the field will be set to
	 * @param fieldName the field which will be set
	 * @throws NoSuchFieldException NoSuchFieldException
	 * @throws IllegalArgumentException IllegalArgumentException
	 * @throws IllegalAccessException IllegalAccessException
	 */
	public static void setFieldValue(final Object object, final Object value, final String fieldName)
			throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
		Class<?> clazz = object.getClass();
		while (clazz != Object.class) {
			try {
				final Field field = clazz.getDeclaredField(fieldName);
				field.setAccessible(true);
				field.set(object, value);
				return;
			}
			catch (final NoSuchFieldException e) {
				clazz = clazz.getSuperclass();
			}
		}
		throw new NoSuchFieldException(fieldName);
	}

	/**
	 * Gets the given object's field value.
	 * @param <T> the return type
	 * @param object the object whose field value will be set
	 * @param fieldName the field which will be retrieved
	 * @return the given object's field value
	 * @throws NoSuchFieldException NoSuchFieldException
	 * @throws IllegalAccessException IllegalAccessException
	 */
	@SuppressWarnings("unchecked")
	public static <T> T getFieldValue(final Object object, final String fieldName)
			throws NoSuchFieldException, IllegalAccessException {
		Class<?> clazz = object.getClass();
		while (clazz != Object.class) {
			try {
				final Field field = clazz.getDeclaredField(fieldName);
				field.setAccessible(true);
				return (T) field.get(object);
			}
			catch (final NoSuchFieldException e) {
				clazz = clazz.getSuperclass();
			}
		}
		throw new NoSuchFieldException(fieldName);
	}

}
