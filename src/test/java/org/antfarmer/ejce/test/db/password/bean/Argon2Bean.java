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
package org.antfarmer.ejce.test.db.password.bean;

import javax.persistence.Entity;
import javax.persistence.Transient;

import org.hibernate.annotations.Parameter;
import org.hibernate.annotations.Type;

/**
 * @author Ameer Antar
 */
@Entity
public class Argon2Bean extends AbstractPasswordBean {

	public static final String STORE_EXPORT_KEY = "org.antfarmer.ejce.encoder.Argon2";

	Argon2Bean() {
		// for Hibernate
	}

	/**
	 * Constructor.
	 * @param password
	 */
	public Argon2Bean(final String password) {
		super(password);
	}

	/**
	 * Returns the password.
	 * @return the password
	 */
	@Override
	@Type(type = "org.antfarmer.ejce.password.EncodedPasswordType", parameters = {
			@Parameter(name = "encoderAdapter", value = "org.antfarmer.ejce.password.encoder.Argon2JvmEncoder"),
			@Parameter(name = "storeExportKey", value = STORE_EXPORT_KEY)
	})
	public String getPassword() {
		return super.getPassword();
	}

	/**
	 * {@inheritDoc}
	 */
	@Transient
	@Override
	public String getStoreExportKey() {
		return STORE_EXPORT_KEY;
	}

}
