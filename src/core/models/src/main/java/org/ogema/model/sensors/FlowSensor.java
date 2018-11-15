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
import org.ogema.core.model.units.FlowResource;
import org.ogema.model.ranges.FlowRange;
import org.ogema.model.targetranges.FlowTargetRange;

/**
 * Flow sensor
 */
public interface FlowSensor extends GenericFloatSensor {
	
	@NonPersistent
	@Override
	FlowResource reading();

	@Override
	FlowRange ratedValues();

	@Override
	FlowTargetRange settings();

	@Override
	FlowTargetRange deviceSettings();

	@Override
	FlowTargetRange deviceFeedback();
}
