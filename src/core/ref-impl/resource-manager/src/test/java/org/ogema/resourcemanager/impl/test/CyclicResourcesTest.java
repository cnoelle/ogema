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
package org.ogema.resourcemanager.impl.test;

import java.util.List;

import static org.junit.Assert.*;

import org.junit.Test;
import org.ogema.core.model.Resource;
import org.ogema.core.model.schedule.Schedule;
import org.ogema.core.model.simple.FloatResource;
import org.ogema.core.resourcemanager.ResourceManagement;
import org.ogema.model.devices.generators.PVPlant;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

/**
 * Tests for the case that cycles (via refences) exist in the resource graph.
 */
@ExamReactorStrategy(PerClass.class)
public class CyclicResourcesTest extends OsgiTestBase {

	public static final String RESNAME = CyclicResourcesTest.class.getSimpleName();

	/**
	 * A made-up cyclical structure of - (A), a PV plant with - (B), an azimuth angle, for which - (C), a definition
	 * schedule exists, which - has a decorator referring to the PV plant this corresponds to.
	 */
	class CyclicStructure {

		private final ResourceManagement resMan;
		public PVPlant pvPlant;
		public FloatResource azimuth;
		public Schedule aziforecast;
		public PVPlant referredPlant;

		/**
		 * Creates the object and remembers the reference to OGEMA. Does not actually create the resources. Use
		 * this.create() for doing so.
		 * 
		 * @param resMan
		 *            Reference to the OGEMA resouce manager to use.
		 */
		public CyclicStructure(final ResourceManagement resMan) {
			this.resMan = resMan;
		}

		/**
		 * Actually create the resources for the structure.
		 * 
		 * @param activate
		 *            iff true, created resources are being activated.
		 */
		public void create(final boolean activate) {
			pvPlant = resMan.createResource(RESNAME + counter++, PVPlant.class);
			assertNotNull(pvPlant);
			azimuth = pvPlant.azimuth().reading();
			azimuth.create();
			assertNotNull(azimuth);
			azimuth.setValue(0.f);
			aziforecast = azimuth.addDecorator("definition", Schedule.class);
			assertNotNull(aziforecast);
			aziforecast.addDecorator("referringObject", pvPlant);
			referredPlant = (PVPlant) aziforecast.getSubResource("referringObject");
			assertTrue(referredPlant.equalsLocation(pvPlant));
			assertFalse(referredPlant.equalsPath(pvPlant));

			if (activate)
				pvPlant.activate(true);
		}
	}

	/**
	 * Tests if getSubResource works. Test fails will probably result in a stack overflow error, owing to the framework
	 * running in an infinite loop.
	 */
	@Test
	public void getAllSubresourcesWorks() {
		CyclicStructure struct = new CyclicStructure(resMan);
		struct.create(true);

		// get all subresrouces recursively
		List<Resource> subres;
		subres = struct.pvPlant.getSubResources(true);
		assertEquals(subres.size(), 4);
		subres = struct.azimuth.getSubResources(true);
		assertEquals(subres.size(), 4);
		subres = struct.aziforecast.getSubResources(true);
		assertEquals(subres.size(), 4);
		subres = struct.referredPlant.getSubResources(true);
		assertEquals(subres.size(), 4);

		// get only subresources of specific type
		List<PVPlant> subpv;
		subpv = struct.pvPlant.getSubResources(PVPlant.class, true);
		assertEquals(subpv.size(), 1);
		subpv = struct.azimuth.getSubResources(PVPlant.class, true);
		assertEquals(subpv.size(), 1);
		subpv = struct.aziforecast.getSubResources(PVPlant.class, true);
		assertEquals(subpv.size(), 1);
		subpv = struct.referredPlant.getSubResources(PVPlant.class, true);
		assertEquals(subpv.size(), 1);
	}
}
