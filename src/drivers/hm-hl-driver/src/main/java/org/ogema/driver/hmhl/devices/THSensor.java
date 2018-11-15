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
package org.ogema.driver.hmhl.devices;

import org.ogema.core.application.ApplicationManager;
import org.ogema.core.channelmanager.driverspi.DeviceLocator;
import org.ogema.core.channelmanager.measurements.Value;
import org.ogema.core.model.simple.FloatResource;
import org.ogema.core.model.simple.IntegerResource;
import org.ogema.core.model.units.TemperatureResource;
import org.ogema.core.resourcemanager.AccessMode;
import org.ogema.core.resourcemanager.AccessPriority;
import org.ogema.driver.hmhl.Constants;
import org.ogema.driver.hmhl.HM_hlConfig;
import org.ogema.driver.hmhl.HM_hlDevice;
import org.ogema.driver.hmhl.HM_hlDriver;
import org.ogema.model.devices.sensoractordevices.SensorDevice;
import org.ogema.model.devices.storage.ElectricityStorage;
import org.ogema.model.sensors.StateOfChargeSensor;
import org.ogema.model.sensors.HumiditySensor;
import org.ogema.model.sensors.TemperatureSensor;
import org.ogema.tools.resource.util.ResourceUtils;

public class THSensor extends HM_hlDevice {

	private FloatResource humidity;

	public enum Status_hum {
		DISABLED, UNKNOWN, ENABLED
	}

	Status_hum humidityEnabled = Status_hum.UNKNOWN;
	private TemperatureResource temperature;
	private FloatResource batteryStatus;
	private SensorDevice thDevice;

	public THSensor(HM_hlDriver driver, ApplicationManager appManager, HM_hlConfig config) {
		super(driver, appManager, config);
	}

	public THSensor(HM_hlDriver driver, ApplicationManager appManager, DeviceLocator deviceLocator) {
		super(driver, appManager, deviceLocator);
		addMandatoryChannels();
	}

	@Override
	protected void parseValue(Value value, String channelAddress) {
		switch (channelAddress) {
		case "ATTRIBUTE:0001":
			temperature.setCelsius(value.getFloatValue());
			temperature.activate(true);
			break;
		case "ATTRIBUTE:0002":
			if (humidityEnabled == Status_hum.UNKNOWN) {
				float hum = 0;
				try {
					hum = value.getFloatValue();
				} catch (NullPointerException e) {
					humidityEnabled = Status_hum.DISABLED;
				}
				if (!(humidityEnabled == Status_hum.DISABLED)) {
					enableHumidity();
					humidity.setValue(hum * 0.01f);
					humidity.activate(false);
				}
			}
			else if (humidityEnabled == Status_hum.ENABLED) {
				humidity.setValue(value.getFloatValue() * 0.01f);
				humidity.activate(false);
			}
			break;
		case "ATTRIBUTE:0003":
			batteryStatus.setValue(value.getFloatValue());
			batteryStatus.activate(true);
			break;
		}
	}

	private void addMandatoryChannels() {
		HM_hlConfig attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0001";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Temperature";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0002";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Humidity";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0003";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_BatteryStatus";
		attributeConfig.chLocator = addChannel(attributeConfig);

		/*
		 * Initialize the resource tree
		 */
		// Create top level resource
		thDevice = resourceManager.createResource(hm_hlConfig.resourceName, SensorDevice.class);
		thDevice.sensors().create();
		// thDevice.sensors().activate(true);

		TemperatureSensor tSensor = thDevice.sensors().addDecorator("temperatureSensor", TemperatureSensor.class);
		temperature = tSensor.reading().create();
		// temperature.activate(true);
		//		temperature.setCelsius(0);
		temperature.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);
		// tSensor.activate(false);
		// thDevice.activate(false);

		ElectricityStorage battery = thDevice.electricityStorage().create();
		IntegerResource batteryType = battery.type().create();
		batteryType.setValue(1); // "generic battery"
		batteryType.activate(false);
		// batteryType.activate(true);
		StateOfChargeSensor eSens = battery.chargeSensor().create();
		batteryStatus = eSens.reading().create();
		// batteryStatus.activate(true);
		// batteryStatus.setValue(95);
		batteryStatus.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);
		// do not activate value resources, since they do not contain sensible values yet
		ResourceUtils.activateComplexResources(thDevice, true, appManager.getResourceAccess());
	}

	private void enableHumidity() {
		humidityEnabled = Status_hum.ENABLED;
		HumiditySensor hSensor = thDevice.sensors().addDecorator("humiditySensor", HumiditySensor.class);
		humidity = hSensor.reading().create();
		//		humidity.activate(true);
		humidity.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);
		hSensor.activate(false);
	}

	@Override
	protected void unifyResourceName(HM_hlConfig config) {
		config.resourceName += Constants.HM_TH_RES_NAME + config.deviceAddress.replace(':', '_');
	}

	@Override
	protected void terminate() {
		removeChannels();
	}
}
