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
package org.antfarmer.ejce.test.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.antfarmer.ejce.util.ObjectUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class ObjectUtilTest {

	@Test
	public void testEquals() {
		final String a = "same";
		final String b = "same";
		final String c = "not";

		assertTrue(ObjectUtil.equals(null, null));
		assertFalse(ObjectUtil.equals(a, null));
		assertFalse(ObjectUtil.equals(null, a));
		assertTrue(ObjectUtil.equals(a, b));
		assertTrue(ObjectUtil.equals(b, a));
		assertFalse(ObjectUtil.equals(a, c));
		assertFalse(ObjectUtil.equals(c, a));
	}
}
