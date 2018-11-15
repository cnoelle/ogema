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
package org.ogema.resourcemanager.impl.transaction.actions;

import org.ogema.core.model.schedule.Schedule;
import org.ogema.core.resourcemanager.transaction.ReadConfiguration;
import org.ogema.core.timeseries.ReadOnlyTimeSeries;
import org.ogema.tools.resource.util.ValueResourceUtils;
import org.ogema.tools.timeseries.implementations.ArrayTimeSeries;

public class ScheduleReadAction extends ResourceReadAction<ReadOnlyTimeSeries, Schedule> {

	private final long[] interval;
	
	public ScheduleReadAction(Schedule resource, ReadConfiguration config, long t0, long t1) {
		super(resource, config);
		this.interval = new long[]{t0,t1};
	}
	
	@Override
	protected ReadOnlyTimeSeries readResource(Schedule resource) {
		return new ArrayTimeSeries(ValueResourceUtils.getValueType(resource)).read(resource,interval[0],interval[1]);
	}

}
