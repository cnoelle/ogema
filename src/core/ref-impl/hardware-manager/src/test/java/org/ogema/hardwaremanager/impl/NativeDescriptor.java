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
package org.ogema.hardwaremanager.impl;

import java.util.HashMap;
import java.util.Map;

import org.ogema.core.hardwaremanager.HardwareDescriptor.HardwareType;

public class NativeDescriptor {
	public String identifier;
	public HardwareType type;
	public String port;
	public Map<String, String> usbInfo;

	public NativeDescriptor() {
		usbInfo = new HashMap<String, String>();
	}

	public NativeDescriptor(String identifer, HardwareType type, String port, Map<String, String> usbInfo) {
		this.identifier = identifer;
		this.type = type;
		this.port = port;
		if (usbInfo == null)
			usbInfo = new HashMap<String, String>();
		this.usbInfo = usbInfo;
	}
}
