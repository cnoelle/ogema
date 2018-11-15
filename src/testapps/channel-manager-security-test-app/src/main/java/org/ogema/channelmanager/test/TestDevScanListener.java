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
package org.ogema.channelmanager.test;

import java.util.LinkedList;
import java.util.List;

import org.ogema.core.channelmanager.driverspi.DeviceLocator;
import org.ogema.core.channelmanager.driverspi.DeviceScanListener;

class TestDevScanListener implements DeviceScanListener {

	public float ratio = 0.f;
	public boolean success = false;
	public boolean finished = false;
	public Exception finishedException = null;
	public List<DeviceLocator> foundDevices = null;

	@Override
	public void deviceFound(DeviceLocator device) {
		if (foundDevices == null)
			foundDevices = new LinkedList<DeviceLocator>();

		foundDevices.add(device);
		System.out.println("FINISHED CALLED");
	}

	@Override
	public void finished(boolean success, Exception e) {
		finished = true;
		System.out.println("FINISHED CALLED");
		this.success = success;
		this.finishedException = e;
	}

	@Override
	public void progress(float ratio) {
		this.ratio = ratio;
	}

}
