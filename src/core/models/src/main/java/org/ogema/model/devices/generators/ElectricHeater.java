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
package org.ogema.model.devices.generators;

import org.ogema.model.devices.buildingtechnology.MechanicalFan;
import org.ogema.model.connections.ElectricityConnection;

/**
 * This interface represents a device that transfers electricity to thermal
 * energy, such as a heat rod.
 */
public interface ElectricHeater extends HeatGenerator {

	/**
	 * Electrical connection that delivers the input power.
	 */
	ElectricityConnection electricityConnection();

	/** 
	 * In case of storage heating: ventilation for transfer of heat from storage to room 
	 */
	MechanicalFan fan();
}
