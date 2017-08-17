/**
 * This file is part of OGEMA.
 *
 * OGEMA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * OGEMA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OGEMA. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ogema.resourcemanager.impl.model.units;

import org.ogema.core.model.Resource;
import org.ogema.core.model.units.FlowResource;
import org.ogema.core.model.units.PhysicalUnit;
import org.ogema.resourcemanager.impl.ApplicationResourceManager;

import org.ogema.resourcemanager.virtual.VirtualTreeElement;

/**
 *
 * @author Timo Fischer, Fraunhofer IWES
 */
public class DefaultFlowResource extends UnitFloatResource implements FlowResource {

	public DefaultFlowResource(VirtualTreeElement el, Class<? extends Resource> unitResourceType, String path,
			ApplicationResourceManager resMan) {
		super(el, unitResourceType, path, resMan);
	}

	@Override
	public final PhysicalUnit getUnit() {
		return PhysicalUnit.CUBIC_METERS_PER_SECOND;
	}

	@Override
	public boolean setCubicMeterPerHour(float value) {
		return setValue(value * 3600);
	}

	@Override
	public float getCubicMeterPerHour() {
		return getValue() / 3600;
	}
}
