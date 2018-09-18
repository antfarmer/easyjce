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
package org.antfarmer.ejce.test.hibernate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.sql.Types;

import org.antfarmer.ejce.hibernate.EncryptedStringType;
import org.junit.Test;

/**
 * @author Ameer Antar
 */
public class StringHibernateTypeTest extends EncryptedStringType {

	@Test
	public void testTypeMethods() throws GeneralSecurityException {

		// assemble
		String o = null;
		assertNull(assemble(o, this));
		o = new String();
		assertSame(o, assemble(o, this));

		// deepCopy
		assertSame(o, deepCopy(o));

		// disassemble
		o = null;
		assertNull(disassemble(o));
		o = new String();
		assertSame(o, disassemble(o));

		// equals
		assertTrue(equals(null, null));
		assertFalse(equals(o, null));
		assertFalse(equals(null, o));
		assertTrue(equals(o, o));
		assertTrue(equals(o, new String()));
		assertTrue(equals(new String(), o));

		// hashCode
		assertSame(o.hashCode(), hashCode(o));

		// isMutable
		assertFalse(isMutable());

		// replace
		assertSame(o, replace(o, "other", this));

		// sqlTypes
		assertArrayEquals(new int[] {Types.VARCHAR}, sqlTypes());

		// returnedClass
		assertSame(String.class, returnedClass());
	}

}
