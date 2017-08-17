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
package org.ogema.drivers.homematic.xmlrpc.hl.types;

import org.ogema.core.model.Resource;
import org.ogema.core.model.simple.BooleanResource;
import org.ogema.core.model.simple.IntegerResource;
import org.ogema.model.devices.storage.ElectricityStorage;

/**
 * Stores information from the channel 'Maintenance' that is available on
 * every HomeMatic device.
 * 
 * @author jlapp
 */
public interface HmMaintenance extends Resource {
    
    IntegerResource errorCode();
    
    IntegerResource rssiDevice();
    
    IntegerResource rssiPeer();
    
    BooleanResource batteryLow();
    
    /**
     * A battery resource should only be created for devices that report
     * an {@code OPERATING_VOLTAGE}, which will be available as
     * {@link ElectricityStorage#internalVoltage() }.
     * @return device battery
     */
    ElectricityStorage battery();
    
}
