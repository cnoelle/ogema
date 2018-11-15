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
package org.ogema.app.DRS485DEconsole;

import java.util.Properties;

import org.ogema.core.application.ApplicationManager;
import org.ogema.core.resourcemanager.ResourceManagement;
import org.ogema.driver.DRS485DE.DRS485DEConfigurationModel;
import org.ogema.model.metering.ElectricityMeter;

/**
 * This class manages the OGEMA resources for one meter instance. It holds references to the configuration resource and
 * if detected, the meter resource.
 * 
 * @author pau
 * 
 */
public class Device {

	/** name of the resource: "DRS485DE_" + index */
	public static final String KEY_NAME = "name";

	/** name of the interface: "COM1", "/dev/ttyUSB1" */
	public static final String KEY_INTERFACE = "interface";

	/** MODBUS device address: "1" */
	public static final String KEY_DEVICE = "device";

	/** Query interval */
	public static final String KEY_INTERVAL = "interval";

	/** Baudrate: "9600" */
	public static final String KEY_BAUDRATE = "baud";

	/** Databits: "8" */
	public static final String KEY_DATABITS = "databits";

	/** Parity: "none", "even", "odd" */
	public static final String KEY_PARITY = "parity";

	/** Stopbits: "1" */
	public static final String KEY_STOPBITS = "stopbits";

	/** flowcontrol: "none" */
	public static final String KEY_FLOWCONTROL = "flowcontrol";

	/** rs485 echo active? "1" : loopback of sent bits, "0" : loopback suppressed */
	public static final String KEY_ECHO = "echo";

	/** receive timeout: "500" */
	public static final String KEY_TIMEOUT = "timeout";

	/** configuration enabled: "0" */
	public static final String KEY_ACTIVE = "active";

	/** the Electricity Meter resource created by the driver for the configuration */
	private ElectricityMeter dataModel;

	/** the configuration resource */
	private DRS485DEConfigurationModel configurationModel;

	/** interface parameters as single strings */
	private Properties interfaceParams;

	/** OGEMA resource management */
	private ResourceManagement resources;

	/** Create a device from an existing configuration resource */
	public Device(ApplicationManager applicationManager, DRS485DEConfigurationModel configurationModel) {
		resources = applicationManager.getResourceManagement();

		interfaceParams = new Properties();

		this.configurationModel = configurationModel;

		parseParameterString(interfaceParams, configurationModel.deviceParameters().getValue());

	}

	/** Create a device and a configuration resource with default parameters */
	public Device(ApplicationManager applicationManager, int index) {
		String uniqueName;

		resources = applicationManager.getResourceManagement();

		interfaceParams = new Properties();

		interfaceParams.setProperty(KEY_BAUDRATE, "9600");
		interfaceParams.setProperty(KEY_DATABITS, "8");
		interfaceParams.setProperty(KEY_PARITY, "N");
		interfaceParams.setProperty(KEY_STOPBITS, "1");
		interfaceParams.setProperty(KEY_FLOWCONTROL, "none");
		interfaceParams.setProperty(KEY_ECHO, "0");
		interfaceParams.setProperty(KEY_TIMEOUT, "500");

		uniqueName = resources.getUniqueResourceName("DRS485DEConfiguration_" + index);
		configurationModel = resources.createResource(uniqueName, DRS485DEConfigurationModel.class);

		configurationModel.addOptionalElement("interfaceId");
		configurationModel.addOptionalElement("deviceAddress");
		configurationModel.addOptionalElement("deviceParameters");
		configurationModel.addOptionalElement("timeout");
		configurationModel.addOptionalElement("resourceName");

		configurationModel.interfaceId().setValue("COM7");
		configurationModel.deviceAddress().setValue("1");
		configurationModel.deviceParameters().setValue(getParameterString(interfaceParams));
		configurationModel.timeout().setValue(1000);

		uniqueName = resources.getUniqueResourceName("DRS485DE_" + index);
		configurationModel.resourceName().setValue(uniqueName);

	}

	/** get configuration values as a property object */
	Properties getProperties() {
		Properties prop = new Properties();

		prop.put(KEY_NAME, configurationModel.resourceName().getValue());
		prop.put(KEY_INTERFACE, configurationModel.interfaceId().getValue());
		prop.put(KEY_DEVICE, configurationModel.deviceAddress().getValue());
		prop.put(KEY_INTERVAL, Integer.toString(configurationModel.timeout().getValue()));
		prop.putAll(interfaceParams);
		prop.put(KEY_ACTIVE, configurationModel.isActive() ? "1" : "0");

		return prop;
	}

	/** set a configuration value */
	void setProperty(String key, String value) {
		switch (key) {
		case KEY_NAME:
			configurationModel.resourceName().setValue(resources.getUniqueResourceName(value));
			break;

		case KEY_INTERFACE:
			configurationModel.interfaceId().setValue(value);
			break;

		case KEY_DEVICE:
			configurationModel.deviceAddress().setValue(value);
			break;

		case KEY_INTERVAL:
			configurationModel.timeout().setValue(Integer.parseInt(value));
			break;

		case KEY_BAUDRATE:
		case KEY_DATABITS:
		case KEY_PARITY:
		case KEY_STOPBITS:
		case KEY_FLOWCONTROL:
		case KEY_ECHO:
		case KEY_TIMEOUT:
			interfaceParams.put(key, value);
			configurationModel.deviceParameters().setValue(getParameterString(interfaceParams));
			break;

		case KEY_ACTIVE:
			if (value.equals("0"))
				configurationModel.deactivate(true);
			else if (value.equals("1"))
				configurationModel.activate(true);
			else
				throw new IllegalArgumentException(KEY_ACTIVE + " must be either '0' or '1'");
			break;

		default:
			throw new IllegalArgumentException("unknown key value " + key);
		}
	}

	/** return parameter string as expected by the modbus driver */
	private String getParameterString(Properties prop) {
		String result;

		result = prop.getProperty(KEY_BAUDRATE);
		result += ":" + prop.getProperty(KEY_DATABITS);
		result += ":" + prop.getProperty(KEY_PARITY);
		result += ":" + prop.getProperty(KEY_STOPBITS);
		result += ":" + prop.getProperty(KEY_FLOWCONTROL);
		result += ":" + prop.getProperty(KEY_FLOWCONTROL);
		result += ":" + prop.getProperty(KEY_ECHO);
		//result += ":" + prop.getProperty(KEY_TIMEOUT);

		return result;
	}

	/** parse parameter string an save values in the property object */
	private void parseParameterString(Properties prop, String parameter) {
		String[] split = parameter.split(":");

		prop.setProperty(KEY_BAUDRATE, split[0]);
		prop.setProperty(KEY_DATABITS, split[1]);
		prop.setProperty(KEY_PARITY, split[2]);
		prop.setProperty(KEY_STOPBITS, split[3]);
		prop.setProperty(KEY_FLOWCONTROL, split[4]);
		// prop.setProperty(KEY_FLOWCONTROL, split[5]);
		prop.setProperty(KEY_ECHO, split[6]);
		//prop.setProperty(KEY_TIMEOUT, split[7]);

	}

	/** get the configuration resource */
	public DRS485DEConfigurationModel getConfigurationModel() {
		return configurationModel;
	}

	/** delete the configuration resource */
	public void delete() {
		configurationModel.delete();
	}

	/** get the name of the data resource */
	public String getResourceName() {
		return configurationModel.resourceName().getValue();
	}

	/** set the data resource */
	public void setDataResource(ElectricityMeter resource) {
		dataModel = resource;
	}

	/** print the data resource values */
	public void printReadings() {
		if (dataModel == null) {
			System.out.println("meter data not available");
		}
		else {
			float energy = dataModel.energyReading().getValue();
			System.out.println("Energy: " + energy + " " + dataModel.energyReading().getUnit() + "("
					+ (energy / 3600000) + " kWh)");
		}
	}
}
