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
package org.ogema.apps.sensorwarning.pattern;

import org.ogema.apps.sensorwarning.model.SensorWarningConfiguration;
import org.ogema.core.model.Resource;
import org.ogema.core.model.simple.BooleanResource;
import org.ogema.core.model.simple.FloatResource;
import org.ogema.core.resourcemanager.AccessMode;
import org.ogema.core.resourcemanager.pattern.ResourcePattern;
import org.ogema.model.actors.OnOffSwitch;
import org.ogema.model.sensors.GenericFloatSensor;

/**
 * Search pattern for complete configurations.
 * 
 * @author Timo Fischer, Fraunhofer IWES
 */
public class ConfiguredSensorPattern extends ResourcePattern<SensorWarningConfiguration> {

	private final OnOffSwitch alarmSwitch = model.alarmSwitch();
	private final GenericFloatSensor sensor = model.sensor();

	/**
	 * Switch to trigger depending on the alarm settings.
	 */
	@Access(mode = AccessMode.EXCLUSIVE)
	public final BooleanResource trigger = alarmSwitch.stateControl();

	/**
	 * Current sensor reading.
	 */
	public final FloatResource reading = sensor.reading();

	/**
	 * Minimum sensor reading. If this does not exist, it cannot be violated.
	 */
	@Existence(required = CreateMode.OPTIONAL)
	public final FloatResource minReading = sensor.settings().alarmLimits().lowerLimit();

	/**
	 * Maximum sensor reading. If this does not exist, it cannot be violated.
	 */
	@Existence(required = CreateMode.OPTIONAL)
	public final FloatResource maxReading = sensor.settings().alarmLimits().upperLimit();

	/**
	 *  Default constructor required by OGEMA. Do not change.
	 */
	public ConfiguredSensorPattern(Resource res) {
		super(res);
	}

	/**
	 * Checks if limits are violated.
	 */
	public boolean areLimitsViolated() {
		final float x = reading.getValue();
		if (minReading.isActive()) {
			final float min = minReading.getValue();
			if (x < min)
				return true;
		}
		if (maxReading.isActive()) {
			final float max = maxReading.getValue();
			if (x > max)
				return true;
		}
		return false;
	}

	/**
	 * Overwritten for easy interactions with Java collections.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ConfiguredSensorPattern) {
			ConfiguredSensorPattern pattern = (ConfiguredSensorPattern) obj;
			return pattern.model.equalsLocation(model);
		}
		return super.equals(obj);
	}

}
