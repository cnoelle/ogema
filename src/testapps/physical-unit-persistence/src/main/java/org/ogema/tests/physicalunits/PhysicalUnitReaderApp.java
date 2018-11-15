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
package org.ogema.tests.physicalunits;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;

import org.ogema.core.application.Application;
import org.ogema.core.application.ApplicationManager;
import org.ogema.core.logging.OgemaLogger;
import org.ogema.core.model.Resource;
import org.ogema.core.model.units.TemperatureResource;
import org.ogema.core.resourcemanager.ResourceManagement;
import org.ogema.core.resourcemanager.ResourceAccess;

// The annotations encapsule the OSGi required. They expose the service Application
// to OSGi, which the OGEMA framework uses to detect this piece of code as an
// OGEMA application.
@Component(specVersion = "1.1", immediate = true)
@Service(Application.class)
public class PhysicalUnitReaderApp implements Application {

	protected OgemaLogger logger;
	protected ApplicationManager appMan;
	protected ResourceManagement resMan;
	protected ResourceAccess resAcc;

	/**
	 * Start method is called by the framework once this application has been
	 * discovered. From the application's perspective, this is where the program
	 * starts. Applications memorize the reference to their ApplicationManager
	 * and usually register timers or resource demands here.
	 *
	 * The example application registers a timer task to be periodically invoked
	 * by the framework.
	 */
	@Override
	public void start(ApplicationManager appManager) {
		// Store references to the application manager and common services for future use.
		this.appMan = appManager;
		this.logger = appManager.getLogger();
		this.resMan = appManager.getResourceManagement();
		this.resAcc = appManager.getResourceAccess();

		test();

	}

	/**
	 * This is called when the application is stopped by the framework.
	 */
	@Override
	public void stop(AppStopReason reason) {
		logger.debug("{} stopped", getClass().getName());
	}

	void test() {
		final String name = resMan.getUniqueResourceName("TemperatureResource");
		final Resource existingResource = resAcc.getResource(name);
		if (existingResource != null) {
			final Class<? extends Resource> type = existingResource.getResourceType();
			if (TemperatureResource.class.isAssignableFrom(type)) {
				logger.error("Resource type of resource " + name + " is " + type.getCanonicalName());
			}
			else {
				throw new RuntimeException("Resource type of resource " + name + " is " + type.getCanonicalName());
			}
		}
		else {
			resMan.createResource(name, TemperatureResource.class);
			logger.info("Created the test resource. Restart framework to check correct resource type.");
		}
	}
}
