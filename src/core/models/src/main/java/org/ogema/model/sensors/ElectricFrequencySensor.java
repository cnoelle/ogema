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
package org.ogema.model.sensors;

import org.ogema.core.model.ModelModifiers.NonPersistent;
import org.ogema.core.model.units.FrequencyResource;
import org.ogema.model.ranges.FrequencyRange;
import org.ogema.model.targetranges.FrequencyTargetRange;

/** GenericFloatSensor for the frequency of alternating current */
public interface ElectricFrequencySensor extends GenericFloatSensor {

	@NonPersistent
	@Override
	FrequencyResource reading();

	@Override
	FrequencyRange ratedValues();

	@Override
	FrequencyTargetRange settings();

	@Override
	FrequencyTargetRange deviceSettings();

	@Override
	FrequencyTargetRange deviceFeedback();
}
