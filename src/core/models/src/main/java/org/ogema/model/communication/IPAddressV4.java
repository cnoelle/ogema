/**
 * Copyright 2011-2018 Fraunhofer-Gesellschaft zur Förderung der angewandten Wissenschaften e.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ogema.model.communication;

import org.ogema.core.model.simple.IntegerResource;
import org.ogema.core.model.simple.StringResource;
import org.ogema.core.model.simple.TimeResource;
import org.ogema.model.prototypes.Data;

/**
 * An IP V4 address.
 */
public interface IPAddressV4 extends Data {
	/** Address as URL or IP address in 4xnumber-3xdot-format */
	public StringResource address();

	/** Address may additionally be provided as long */
	public TimeResource ipAddress();

	/** Port if specified */
	public IntegerResource port();

	/**
	 * MAC address attached to the IPAddress (from the perspective of the gateway) may be added if known/relevant
	 */
	public StringResource macAddress();
}
