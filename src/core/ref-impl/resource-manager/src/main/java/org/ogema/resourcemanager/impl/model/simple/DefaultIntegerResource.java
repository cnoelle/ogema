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
package org.ogema.resourcemanager.impl.model.simple;

import org.ogema.core.model.schedule.AbsoluteSchedule;
import org.ogema.core.model.simple.IntegerResource;
import org.ogema.core.recordeddata.RecordedData;
import org.ogema.core.resourcemanager.AccessMode;
import org.ogema.core.resourcemanager.ResourceAccessException;
import org.ogema.core.resourcemanager.VirtualResourceException;
import org.ogema.resourcemanager.impl.ApplicationResourceManager;
import org.ogema.resourcemanager.impl.model.schedule.HistoricalSchedule;
import org.ogema.resourcemanager.virtual.VirtualTreeElement;
import org.ogema.resourcetree.SimpleResourceData;

/**
 * 
 * @author jlapp
 */
public class DefaultIntegerResource extends SingleValueResourceBase implements IntegerResource {

	public DefaultIntegerResource(VirtualTreeElement el, String path, ApplicationResourceManager resMan) {
		super(el, path, resMan);
	}

	@Override
	public int getValue() {
		checkReadPermission();
		return getEl().getData().getInt();
	}

	@Override
	public boolean setValue(int value) {
		resMan.lockRead();
		try {
			final VirtualTreeElement el = getElInternal();
			if (el.isVirtual() || getAccessModeInternal() == AccessMode.READ_ONLY) {
				return false;
			}
			checkWritePermission();
			final SimpleResourceData data = el.getData();
			boolean changed = value != data.getInt();
			data.setInt(value);
			handleResourceUpdateInternal(changed);
		} finally {
			resMan.unlockRead();
		}
		return true;
	}

	@Override
	public RecordedData getHistoricalData() {
		checkReadPermission();
		return getResourceDB().getRecordedData(getEl());
	}

	@Override
	public AbsoluteSchedule forecast() {
		return getSubResource("forecast", AbsoluteSchedule.class);
	}

	@Override
	public AbsoluteSchedule program() {
		return getSubResource("program", AbsoluteSchedule.class);
	}

	@Override
	public AbsoluteSchedule historicalData() {
		return getSubResource(HistoricalSchedule.PATH_IDENTIFIER, AbsoluteSchedule.class);
	}

	@Override
	public int getAndSet(final int value) throws VirtualResourceException, SecurityException, ResourceAccessException {
		return getAndWriteInternal(value, false);
	}

	@Override
	public int getAndAdd(final int value) throws VirtualResourceException, SecurityException, ResourceAccessException {
		return getAndWriteInternal(value, true);
	}
	
	private final int getAndWriteInternal(final int value, final boolean addOrSet) {
		if (!exists())
			throw new VirtualResourceException("Resource " + path + " is virtual, cannot set value");
		checkWriteAccess();
		// expensive; we make use of the fact that all access to the SimpleResourceData is 
		// guarded by the resMan lock. 
		resMan.lockWrite(); 
		try {
			final int val = getValue();
			setValue(addOrSet ? (val + value) : value);
			return val;
		} finally {
			resMan.unlockWrite();
		}
	}

}
