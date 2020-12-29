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
package org.ogema.core.model.units;

import org.ogema.core.model.simple.FloatResource;

/**
 * Resource representing an energy physical value.
 */
public interface EnergyResource extends PhysicalUnitResource {

	/**
	 * Returns the energy in Joule.
	 *
	 * @see FloatResource#getValue()
	 */
	@Override
	float getValue();

	/**
	 * Sets the energy to a new value. Unit is Joule.
	 *
	 * @see FloatResource#getValue()
	 */
	@Override
	boolean setValue(float value);

	/**
	 * Returns "J" (the default) or the unit set through {@link #setUnit}.
	 *
	 * @see PhysicalUnitResource#getUnit()
	 */
	@Override
	PhysicalUnit getUnit();
    
    /**
     * Set this resource's unit.
     * 
     * @param u the new unit.
     */
    void setUnit(PhysicalUnit u);
	
	/**
	 * Get the energy in kWhs.
	 */
	float getKWhs();
	
	/**
	 * Set the energy in kWhs. Note that the method 
	 * {@link #getValue()} will still return the value in J.
	 * @param value
	 * 		energy in kWh
	 */
	void setKWhs(float value);
}
