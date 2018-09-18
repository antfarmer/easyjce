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
package org.antfarmer.ejce.test.hibernate;

import org.antfarmer.ejce.hibernate.AbstractHibernateType;
import org.antfarmer.ejce.hibernate.EncryptedDoubleType;

/**
 *
 * @author Ameer Antar
 * @version 1.0
 */
public class EncryptedDoubleTypeTest extends AbstractEncryptedTypeTest<Double> {

	private static final Double TEST_VALUE = 6.66666666;

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected AbstractHibernateType createHibernateType() {
		return new EncryptedDoubleType();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Object getTestValue() {
		return TEST_VALUE;
	}

}
