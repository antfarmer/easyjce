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
package org.antfarmer.ejce.test.db.encryptor.bean;

import javax.persistence.Column;
import javax.persistence.Entity;

import org.hibernate.annotations.Parameter;
import org.hibernate.annotations.Type;

/**
 * @author Ameer Antar
 */
@Entity
public class TextBean extends AbstractEncryptedValueBean<String> {

	private String value;

	TextBean() {
		// for Hibernate
	}

	/**
	 * Constructor.
	 * @param value the value
	 */
	public TextBean(final String value) {
		this.value = value;
	}

	/**
	 * Returns the value.
	 * @return the value
	 */
	@Override
	@Type(type = "org.antfarmer.ejce.hibernate.EncryptedTextType", parameters = {
			@Parameter(name = "paramClass", value = "org.antfarmer.ejce.parameter.AesParameters"),
			@Parameter(name = "paramEncoder", value = "org.antfarmer.ejce.encoder.Base64Encoder"),
			@Parameter(name = "key", value = "mZKfvksbC1PhCvucsAcHMFqT/6s/xuJfmZs2QK+UGOw"),
			@Parameter(name = "encoder", value = "org.antfarmer.ejce.encoder.Base64Encoder"),
			@Parameter(name = "streamLobs", value = "true"),
			@Parameter(name = "streamBuffSize", value = "4096"),
			@Parameter(name = "maxInMemBuffSize", value = "16384")
	})
	@Column(length = 1100 * 1024)
	public String getValue() {
		return value;
	}

	/**
	 * Sets the value.
	 * @param value the value to set
	 */
	public void setValue(final String value) {
		this.value = value;
	}

}
