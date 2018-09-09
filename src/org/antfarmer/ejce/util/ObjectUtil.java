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
 * Object-related utilities.
 * @author Ameer Antar
 */
public class ObjectUtil {

    /**
     * Return true if the two given objects are equal.
     * @param a object a
     * @param b object b
     * @return true if the two given objects are equal; false otherwise
     */
    public static boolean equals(final Object a, final Object b) {
        return (a == b) || (a != null && a.equals(b));
    }

}
