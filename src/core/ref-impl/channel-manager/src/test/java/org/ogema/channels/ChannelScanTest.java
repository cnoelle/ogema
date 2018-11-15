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
package org.ogema.channels;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.ogema.core.channelmanager.driverspi.ChannelLocator;
import org.ogema.core.channelmanager.driverspi.ChannelScanListener;
import org.ogema.core.channelmanager.driverspi.DeviceLocator;

public class ChannelScanTest {

	private ChannelManagerImpl channelManager;

	private ChannelDriverImpl driver;

	@Before
	public void setup() {
		
		channelManager = new ChannelManagerImpl();
		
		channelManager.appreg = new ApplicationRegistryImpl();
		channelManager.permMan = new PermissionManagerImpl();
		
		driver = new ChannelDriverImpl("driver1", "firstDriver");
		channelManager.addDriver(driver);
	}
	
	private DeviceLocator createDeviceLocator(String driverName, String interfaceName, String deviceAddress, String parameters) {
		return new DeviceLocator(driverName, interfaceName, deviceAddress, parameters);
	}
	
	private ChannelLocator createChannelLocator(String channelAddress, DeviceLocator deviceLocator) {
		return new ChannelLocator(channelAddress, deviceLocator);
	}
	
	@Test
	public void testChannelScanSync() throws Exception {
		
		DeviceLocator device = createDeviceLocator(driver.getDriverId(), "", "", null);
		
		List<ChannelLocator> list = new ArrayList<ChannelLocator>();
		list.add(createChannelLocator("1", device));
		list.add(createChannelLocator("2", device));
		list.add(createChannelLocator("3", device));
		list.add(createChannelLocator("4", device));
		list.add(createChannelLocator("5", device));
		
		driver.channelLists.put(device, list);
		
		List<ChannelLocator> channels = channelManager.discoverChannels(device);
		
		for(ChannelLocator channel : channels) {
			assertTrue(list.contains(channel));
		}
		
		assertTrue(channels.size() == list.size());
	}
	
	@Test
	public void testChannelScanAsync() throws Exception {

		DeviceLocator device = createDeviceLocator(driver.getDriverId(), "", "", null);
		
		List<ChannelLocator> list = new ArrayList<ChannelLocator>();
		list.add(createChannelLocator("1", device));
		list.add(createChannelLocator("2", device));
		list.add(createChannelLocator("3", device));
		list.add(createChannelLocator("4", device));
		list.add(createChannelLocator("5", device));
		
		driver.channelLists.put(device, list);
		
		ChannelScanListenerImpl listener = new ChannelScanListenerImpl();
		
		channelManager.discoverChannels(device, listener);
		
		assertTrue(listener.finished);
		assertTrue(listener.success);
	
		for(ChannelLocator channel : listener.channels) {
			assertTrue(list.contains(channel));
		}
	}
	
	@Test
	public void testChannelScanProgress() throws Exception {
		DeviceLocator device = createDeviceLocator(driver.getDriverId(), "", "", null);
		ChannelScanListenerImpl listener = new ChannelScanListenerImpl();
		
		driver.async = true;
		
		channelManager.discoverChannels(device, listener);
		
		driver.channelScanListener.progress(0.0f);
		driver.channelScanListener.progress(0.1f);
		driver.channelScanListener.progress(0.2f);
		driver.channelScanListener.progress(0.5f);
		driver.channelScanListener.progress(0.7f);
		driver.channelScanListener.progress(1.0f);
		driver.channelScanListener.finished(true);
		
		assertTrue(listener.finished);
		assertTrue(listener.success);
		
		assertEquals(6, listener.progressCount);
	}
	
	@Test
	public void testChannelScanListenerException() throws Exception {
		DeviceLocator device = createDeviceLocator(driver.getDriverId(), "", "", null);
		ChannelLocator channel = createChannelLocator("1", device);
		ChannelScanListenerImpl listener = new ChannelScanListenerImpl();
		
		driver.async = true;
		
		channelManager.discoverChannels(device, listener);

		listener.ex = new RuntimeException();
		
		driver.channelScanListener.channelFound(channel);
		driver.channelScanListener.finished(true);
		
		assertTrue(listener.finished);
		assertTrue(listener.success);
		
	}
	
	@Test
	public void testGetChannelList() throws Exception {
		DeviceLocator device = createDeviceLocator(driver.getDriverId(), "", "", null);
		
		List<ChannelLocator> list = new ArrayList<ChannelLocator>();
		list.add(createChannelLocator("1", device));
		list.add(createChannelLocator("2", device));
		
		driver.channelLists.put(device, list);
		
		List<ChannelLocator> result = channelManager.getChannelList(device);
		
		assertEquals(list.size(), result.size());
		assertEquals(2, result.size());
		
		for(int i = 0; i < list.size(); i++) {
			assertEquals(list.get(i), result.get(i));
		}
	}
	
	private class ChannelScanListenerImpl implements ChannelScanListener {

		List<ChannelLocator> channels = new ArrayList<ChannelLocator>();
		boolean success;
		boolean finished;
		int progressCount;
		
		RuntimeException ex;
		
		@Override
		public void channelFound(ChannelLocator channel) {
			
			if (ex != null)
				throw ex;
			
			channels.add(channel);
		}

		@Override
		public void finished(boolean success) {
			finished = true;
			this.success = success;
		}

		@Override
		public void progress(float ratio) {
			progressCount++;
		}
	}
}
