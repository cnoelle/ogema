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

import static org.ogema.core.recordeddata.RecordedDataConfiguration.StorageType.FIXED_INTERVAL;

import org.ogema.core.application.ApplicationManager;
import org.ogema.core.channelmanager.ChannelConfiguration;
import org.ogema.core.channelmanager.driverspi.DeviceLocator;
import org.ogema.core.channelmanager.measurements.BooleanValue;
import org.ogema.core.channelmanager.measurements.Value;
import org.ogema.core.model.simple.BooleanResource;
import org.ogema.core.model.units.ElectricCurrentResource;
import org.ogema.core.model.units.EnergyResource;
import org.ogema.core.model.units.FrequencyResource;
import org.ogema.core.model.units.PowerResource;
import org.ogema.core.model.units.VoltageResource;
import org.ogema.core.recordeddata.RecordedDataConfiguration;
import org.ogema.core.resourcemanager.AccessMode;
import org.ogema.core.resourcemanager.AccessPriority;
import org.ogema.core.resourcemanager.ResourceValueListener;
import org.ogema.driver.hmhl.Constants;
import org.ogema.driver.hmhl.HM_hlConfig;
import org.ogema.driver.hmhl.HM_hlDevice;
import org.ogema.driver.hmhl.HM_hlDriver;
import org.ogema.model.connections.ElectricityConnection;
import org.ogema.model.devices.sensoractordevices.SingleSwitchBox;
import org.ogema.model.sensors.ElectricCurrentSensor;
import org.ogema.model.sensors.ElectricFrequencySensor;
import org.ogema.model.sensors.ElectricPowerSensor;
import org.ogema.model.sensors.ElectricVoltageSensor;
import org.ogema.model.sensors.EnergyAccumulatedSensor;
import org.ogema.tools.resource.util.ResourceUtils;

public class PowerMeter extends HM_hlDevice implements ResourceValueListener<BooleanResource> {

	private BooleanResource onOff;
	private BooleanResource isOn;
	private ElectricCurrentResource iRes;
	private VoltageResource vRes;
	private PowerResource pRes;
	private FrequencyResource fRes;
	private EnergyResource eRes;

	public PowerMeter(HM_hlDriver driver, ApplicationManager appManager, HM_hlConfig config) {
		super(driver, appManager, config);
	}

	public PowerMeter(HM_hlDriver driver, ApplicationManager appManager, DeviceLocator dl) {
		super(driver, appManager, dl);
		addMandatoryChannels();
	}

	@Override
	protected void parseValue(Value value, String channelAddress) {
		switch (channelAddress) {
		case "ATTRIBUTE:0001":
			isOn.setValue(value.getBooleanValue());
			isOn.activate(true);
			break;
		case "ATTRIBUTE:0002":
			iRes.setValue(value.getFloatValue());
			iRes.activate(true);
			break;
		case "ATTRIBUTE:0003":
			vRes.setValue(value.getFloatValue());
			vRes.activate(true);
			break;
		case "ATTRIBUTE:0004":
			pRes.setValue(value.getFloatValue());
			pRes.activate(true);
			break;
		case "ATTRIBUTE:0005":
			fRes.setValue(value.getFloatValue());
			fRes.activate(true);
			break;
		case "ATTRIBUTE:0006":
			eRes.setValue(value.getFloatValue());
			eRes.activate(true);
			break;
		case "COMMAND:01":
			onOff.setValue(value.getBooleanValue());
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
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Attribute_" + "State";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0002";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Attribute_" + "Current";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0003";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Attribute_" + "Voltage";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0004";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Attribute_" + "Power";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0005";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Attribute_" + "Frequence";
		attributeConfig.chLocator = addChannel(attributeConfig);

		attributeConfig = new HM_hlConfig();
		attributeConfig.driverId = hm_hlConfig.driverId;
		attributeConfig.interfaceId = hm_hlConfig.interfaceId;
		attributeConfig.deviceAddress = hm_hlConfig.deviceAddress;
		attributeConfig.channelAddress = "ATTRIBUTE:0006";
		attributeConfig.timeout = -1;
		attributeConfig.resourceName = hm_hlConfig.resourceName + "_Attribute_" + "Energy";
		attributeConfig.chLocator = addChannel(attributeConfig);

		HM_hlConfig commandConfig = new HM_hlConfig();
		commandConfig.driverId = hm_hlConfig.driverId;
		commandConfig.interfaceId = hm_hlConfig.interfaceId;
		commandConfig.channelAddress = "COMMAND:01";
		commandConfig.resourceName = hm_hlConfig.resourceName + "_Command_" + "OnOffToggle";
		commandConfig.timeout = -1;
		commandConfig.chLocator = addChannel(commandConfig);

		/*
		 * Initialize the resource tree
		 */
		// Create top level resource
		SingleSwitchBox powerMeter = resourceManager.createResource(hm_hlConfig.resourceName, SingleSwitchBox.class);
		// The on/off switch
		powerMeter.onOffSwitch().create();
		onOff = (BooleanResource) powerMeter.onOffSwitch().stateControl().create();
		onOff.requestAccessMode(AccessMode.SHARED, AccessPriority.PRIO_HIGHEST);

		isOn = (BooleanResource) powerMeter.onOffSwitch().stateFeedback().create();
		// isOn.activate(true);
		isOn.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);

		BooleanResource controllable = powerMeter.onOffSwitch().controllable().create();
		controllable.setValue(true);
		controllable.activate(true);

		// The connection attribute and its children, current, voltage, power,
		// frequency
		ElectricityConnection conn = powerMeter.electricityConnection().create();
		// conn.activate(true);

		ElectricCurrentSensor iSens = conn.currentSensor().create();
		iRes = iSens.reading().create();
		// iRes.activate(true);
		// iRes.setValue(0);
		iRes.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);

		ElectricVoltageSensor vSens = (ElectricVoltageSensor) conn.voltageSensor().create();
		vRes = (VoltageResource) vSens.reading().create();
		// vRes.activate(true);
		// vRes.setValue(0);
		vRes.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);

		ElectricPowerSensor pSens = (ElectricPowerSensor) conn.powerSensor().create();
		pRes = (PowerResource) pSens.reading().create();
		// pRes.activate(true);
		// pRes.setValue(0);
		pRes.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);

		ElectricFrequencySensor fSens = (ElectricFrequencySensor) conn.frequencySensor().create();
		fRes = (FrequencyResource) fSens.reading().create();
		// fRes.activate(true);
		// fRes.setValue(0);
		fRes.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);

		// Add accumulated energy attribute
		EnergyAccumulatedSensor energy = powerMeter.electricityConnection().energySensor().create();
		eRes = (EnergyResource) energy.reading().create();
		// eRes.activate(true);
		// eRes.setValue(0);
		eRes.requestAccessMode(AccessMode.EXCLUSIVE, AccessPriority.PRIO_HIGHEST);
		// powerMeter.activate(true);

		// do not activate value resources, since they do not contain sensible values yet
		ResourceUtils.activateComplexResources(powerMeter, true, appManager.getResourceAccess());
		onOff.activate(true);

		// Add listener to register on/off commands
		onOff.addValueListener(this, true);

		// configureLogging();
	}

	@SuppressWarnings("unused")
	private void configureLogging() {
		// configure temperature for logging once per minute
		final RecordedDataConfiguration powerConf = new RecordedDataConfiguration();
		powerConf.setStorageType(FIXED_INTERVAL);
		powerConf.setFixedInterval(60 * 1000l);
		pRes.getHistoricalData().setConfiguration(powerConf);

		// configure state-feedback for logging
		final RecordedDataConfiguration currentConfig = new RecordedDataConfiguration();
		currentConfig.setStorageType(FIXED_INTERVAL);
		currentConfig.setFixedInterval(60 * 1000l);
		iRes.getHistoricalData().setConfiguration(currentConfig);
	}

	@Override
	protected void unifyResourceName(HM_hlConfig config) {
		config.resourceName += Constants.HM_POWER_RES_NAME + config.deviceAddress.replace(':', '_');
	}

	@Override
	public void resourceChanged(BooleanResource resource) {
		// Here the on/off command channel should be written
		// Currently only 1 channel for everything
		ChannelConfiguration locator = this.commandChannel.get("COMMAND:01");
		BooleanValue onOff = new BooleanValue(resource.getValue());
		if (isOn.getValue() != resource.getValue()) {
			// Toggle
			writeToChannel(locator, onOff);
		}
	}

	@Override
	protected void terminate() {
		removeChannels();
	}
}
