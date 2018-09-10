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

import javax.persistence.MappedSuperclass;
import javax.persistence.Transient;

import org.antfarmer.ejce.test.db.AbstractBean;

/**
 * @author Ameer Antar
 */
@MappedSuperclass
public abstract class AbstractPasswordBean extends AbstractBean {

	private String password;

	AbstractPasswordBean() {
		// for Hibernate
	}

	/**
	 * Constructor.
	 * @param password
	 */
	public AbstractPasswordBean(final String password) {
		this.password = password;
	}

	/**
	 * Returns the password.
	 * @return the password
	 */
	@Transient
	public String getPassword() {
		return password;
	}

	/**
	 * Sets the password.
	 * @param password the password to set
	 */
	public void setPassword(final String password) {
		this.password = password;
	}

	@Transient
	public abstract String getStoreExportKey();
}
