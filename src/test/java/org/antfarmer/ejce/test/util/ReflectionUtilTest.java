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

import static org.junit.Assert.assertEquals;

import org.antfarmer.ejce.util.ReflectionUtil;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class ReflectionUtilTest {

	private static final String VALUE = "text";
	private static final String NEW_VALUE = "something else";

	@Test
	public void testGetSet() throws NoSuchFieldException, IllegalAccessException {
		final VisibleClass o = new VisibleClass();
		assertEquals(VALUE, ReflectionUtil.getFieldValue(o, "variable"));

		ReflectionUtil.setFieldValue(o, NEW_VALUE, "variable");
		assertEquals(NEW_VALUE, o.getVariable());
		assertEquals(NEW_VALUE, ReflectionUtil.getFieldValue(o, "variable"));
	}

	@Test
	public void testGetSetInvis() throws NoSuchFieldException, IllegalAccessException {
		final NotVisibleClass o = new NotVisibleClass();
		assertEquals(VALUE, ReflectionUtil.getFieldValue(o, "variable"));

		ReflectionUtil.setFieldValue(o, NEW_VALUE, "variable");
		assertEquals(NEW_VALUE, o.getVariable());
		assertEquals(NEW_VALUE, ReflectionUtil.getFieldValue(o, "variable"));
	}

	@Test(expected = NoSuchFieldException.class)
	public void testGetWrongField() throws NoSuchFieldException, IllegalAccessException {
		final VisibleClass o = new VisibleClass();
		ReflectionUtil.getFieldValue(o, "var");
	}

	@Test(expected = NoSuchFieldException.class)
	public void testSetWrongField() throws NoSuchFieldException, IllegalAccessException {
		final VisibleClass o = new VisibleClass();
		ReflectionUtil.setFieldValue(o, NEW_VALUE, "var");
	}

	public static class VisibleClass {
		private String variable;
		public VisibleClass() {
			setVariable(VALUE);
		}
		public String getVariable() {
			return variable;
		}
		public void setVariable(final String variable) {
			this.variable = variable;
		}
	}

	private static class NotVisibleClass {
		private String variable;
		public NotVisibleClass() {
			setVariable(VALUE);
		}
		public String getVariable() {
			return variable;
		}
		public void setVariable(final String variable) {
			this.variable = variable;
		}
	}
}
