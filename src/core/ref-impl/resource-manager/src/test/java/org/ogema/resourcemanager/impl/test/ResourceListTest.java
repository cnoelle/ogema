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

import org.ogema.exam.ResourceAssertions;
import org.ogema.exam.StructureTestListener;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

import org.junit.Assert;
import org.junit.Test;
import org.ogema.core.model.Resource;
import org.ogema.core.model.ResourceList;
import org.ogema.core.model.simple.BooleanResource;
import org.ogema.core.model.simple.StringResource;
import org.ogema.core.model.units.PowerResource;
import org.ogema.core.resourcemanager.InvalidResourceTypeException;
import org.ogema.core.resourcemanager.ResourceException;

import static org.ogema.core.resourcemanager.ResourceStructureEvent.EventType.SUBRESOURCE_ADDED;
import static org.ogema.core.resourcemanager.ResourceStructureEvent.EventType.SUBRESOURCE_REMOVED;

import org.ogema.exam.ValueTestListener;
import org.ogema.model.actors.OnOffSwitch;
import org.ogema.model.devices.buildingtechnology.ElectricLight;
import org.ogema.model.devices.buildingtechnology.Thermostat;
import org.ogema.model.devices.whitegoods.CoolingDevice;
import org.ogema.model.locations.Room;
import org.ogema.model.locations.WorkPlace;
import org.ogema.model.metering.ElectricityMeter;
import org.ogema.model.prototypes.PhysicalElement;
import org.ogema.model.smartgriddata.ElectricityPrice;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

/**
 * @author jlapp
 */
@ExamReactorStrategy(PerClass.class)
public class ResourceListTest extends OsgiTestBase {

	public static final String RESNAME = OsgiTestBase.class.getSimpleName();
	Room room;

	protected ResourceList<WorkPlace> createTestResource() {
		room = resMan.createResource("room" + counter++, Room.class);
		room.workPlaces().create();
		@SuppressWarnings("unused")
		ResourceList<WorkPlace> wps = room.workPlaces();
		return room.workPlaces();
	}

	@Test
	// ... on resource objects
	//note: works with ASM-generated byte code but not with Java dynamic proxies.
	public void genericListTypeIsAvailableViaReflection() throws Exception {
		createTestResource();
		Method wpsAccess = room.getClass().getMethod("workPlaces");

		Type gType = wpsAccess.getGenericReturnType();
		assertTrue(gType instanceof ParameterizedType);
		@SuppressWarnings("rawtypes")
		Class<?> typeParameter = (Class) ((ParameterizedType) gType).getActualTypeArguments()[0];
		assertEquals(WorkPlace.class, typeParameter);
	}

	@Test
	public void elementTypeIsCorrect() {
		@SuppressWarnings("unused")
		ResourceList<WorkPlace> wps = createTestResource();
		assertEquals(WorkPlace.class, room.workPlaces().getElementType());
	}

	@Test
	public void resourceTypeIsCorrect() {
		@SuppressWarnings("unused")
		ResourceList<WorkPlace> wps = createTestResource();
		final Class<? extends Resource> resType = room.workPlaces().getResourceType();
		assertEquals(ResourceList.class, resType);
	}

	@Test
	public void getSubResourcesByTypeFindsResourceLists() {
		ResourceList<WorkPlace> wps = createTestResource();
		//XXX this cannot currently be expressed without generating a compiler warning
		@SuppressWarnings("rawtypes")
		List<ResourceList> l = room.getSubResources(ResourceList.class, true);
		assertFalse(l.isEmpty());
		assertEquals(1, l.size());
		assertEquals(wps, l.get(0));
	}

	@Test
	public void addingToOptionalComplexArrayWorks() throws ResourceException {
		ResourceList<WorkPlace> wps = createTestResource();
		WorkPlace wp1 = wps.add();
		assertTrue(wp1.exists());
		assertEquals(1, wps.size());
		assertEquals(wp1, wps.getSubResource(wp1.getName()));
		assertTrue(wps.getAllElements().contains(wp1));
	}

	@Test
	public void addingMultipleToOptionalComplexArrayWorks() throws ResourceException {
		ResourceList<WorkPlace> wps = createTestResource();
		final List<WorkPlace> workPlaces = new ArrayList<>();
		for (int i = 0; i < 5; ++i) {
			final WorkPlace wp = wps.add();
			workPlaces.add(wp);
			for (WorkPlace place : workPlaces) {
				assertTrue(wps.getAllElements().contains(place));
			}
			assertEquals(workPlaces.size(), wps.getAllElements().size());
		}
	}

	@Test
	public void elementsAddedViaResourceMethodsAppearInArray() {
		ResourceList<WorkPlace> wps = createTestResource();
		WorkPlace wp1 = wps.add();
		WorkPlace wp2 = wps.addDecorator("fnord", wps.getElementType());
		assertEquals(2, wps.size());
		assertTrue(wps.getAllElements().contains(wp1));
		assertTrue(wps.getAllElements().contains(wp2));
	}

	@Test
	public void elementsAddedViaResourceMethodsAppearInArray2() {
		ResourceList<WorkPlace> wps = createTestResource();
		WorkPlace wp1 = wps.add();
		WorkPlace wp2 = wps.getSubResource("fnord", WorkPlace.class).create();
		assertEquals(2, wps.size()); // fails
		assertTrue(wps.getAllElements().contains(wp1));
		assertTrue(wps.getAllElements().contains(wp2));
	}

	@Test
	public void resourceListReturnsResourcesOfDerivedType() {
		@SuppressWarnings("unchecked")
		ResourceList<PhysicalElement> list = resMan.createResource(newResourceName(), ResourceList.class);
		list.setElementType(PhysicalElement.class);
		list.addDecorator("deco1", ElectricLight.class);
		assertEquals(1, list.getAllElements().size());
		list.add();
		Thermostat thermo = resMan.createResource("thermo", Thermostat.class);
		CoolingDevice cd = resMan.createResource("cd", CoolingDevice.class);
		list.add(thermo);
		assertEquals(3, list.getAllElements().size());
		list.addDecorator("deco4", cd);
		assertEquals(4, list.getAllElements().size());
		list.getSubResource("deco5", CoolingDevice.class).create();
		assertEquals(5, list.getAllElements().size());
		cd.delete();
		list.delete();
		thermo.delete();
	}

	@Test(expected = IllegalStateException.class)
	public void resourceListWithTypeNotSetCausesException() {
		@SuppressWarnings("unchecked")
		ResourceList<Resource> list = resMan.createResource(newResourceName(), ResourceList.class);
		assertNull(list.getElementType());
		list.addDecorator("deco", CoolingDevice.class);
		assertEquals(0, list.getAllElements().size());
		list.add(); //adding to list of undefined type should cause exception
	}

	@Test
	public void referencesAddedViaResourceMethodsAppearInArray() {
		ResourceList<WorkPlace> wps = createTestResource();
		@SuppressWarnings("unused")
		ResourceList<WorkPlace> wps2 = createTestResource();
		// WorkPlace wpExt = wps2.add();
		Room r = resMan.createResource("room", Room.class);
		WorkPlace wpExt = r.addDecorator("xyz", WorkPlace.class);
		assertNotNull(wpExt);
		WorkPlace wp1 = wps.add();
		wps.addDecorator("fnord", wpExt);
		assertEquals(2, wps.size());
		assertTrue(wps.getAllElements().contains(wp1));
		WorkPlace wpRef = (WorkPlace) wps.getSubResource("fnord");
		assertNotNull(wpRef);
		assertTrue(wps.getAllElements().contains(wpRef));
	}

	@Test
	public void containsWorksOnLocation() {
		ResourceList<WorkPlace> wps = createTestResource();
		ResourceList<WorkPlace> wps2 = createTestResource();

		WorkPlace wp1 = wps.addDecorator("test", WorkPlace.class);
		WorkPlace wp2 = wps2.add();
		wps.add(wp2);

		assertTrue(wps.contains(wp1));
		assertTrue(wps.contains(wps2.getAllElements().get(0)));

		WorkPlace notInList = resMan.createResource(newResourceName(), WorkPlace.class);
		assertFalse(wps.contains(notInList));
	}

	@Test
	public void resourceListOfResourceListsWork() {
		@SuppressWarnings("unchecked")
		ResourceList<Resource> rl1 = resMan.createResource(newResourceName(), ResourceList.class);
		rl1.setElementType(Resource.class);
		@SuppressWarnings("unchecked")
		ResourceList<Resource> rl2 = resMan.createResource(newResourceName(), ResourceList.class);
		rl2.setElementType(Resource.class);

		Resource res = resMan.createResource(newResourceName(), WorkPlace.class);
		rl2.add(res);

		rl1.add(rl2);

		assertTrue(rl1.getAllElements().get(0).getSubResources(false).get(0).equalsLocation(res));
	}

	@Test
	public void addingResourceListAsDecoratorWorks() {
		Room r = resMan.createResource(newResourceName(), Room.class);
		//XXX possible to change the API so this can work without a warning?
		@SuppressWarnings("unchecked")
		ResourceList<StringResource> list = r.addDecorator("fnord", ResourceList.class);
		assertNull(list.getElementType());
		list.setElementType(StringResource.class);
		StringResource str = list.add();
		assertNotNull(str);
	}

	@Test
	public void settingResourceListAsOptionalElementWorks() {
		Room room1 = resMan.createResource(newResourceName(), Room.class);
		Room room2 = resMan.createResource(newResourceName(), Room.class);

		room1.workPlaces().create();
		@SuppressWarnings("unused")
		WorkPlace wp1 = room1.workPlaces().add();
		room2.workPlaces().setAsReference(room1.workPlaces());

		assertTrue(room2.workPlaces().exists());
		assertFalse(room2.workPlaces().getAllElements().isEmpty());
	}

	@Test(expected = InvalidResourceTypeException.class)
	public void settingResourceListAsOptionalElementChecksListType() {
		Room room1 = resMan.createResource(newResourceName(), Room.class);
		ResourceList<?> listDecorator = room1.addDecorator("foo", ResourceList.class);
		listDecorator.setElementType(OnOffSwitch.class);
		listDecorator.addDecorator("fnord", OnOffSwitch.class);

		assertEquals(OnOffSwitch.class, listDecorator.getElementType());

		room1.workPlaces().setAsReference(listDecorator);
	}

	@Test
	public void structureListenerWorksWithAddAndRemove() throws InterruptedException {
		StructureTestListener l = new StructureTestListener();

		ResourceList<WorkPlace> list = createTestResource();
		list.addStructureListener(l);
		WorkPlace element = list.add();
		assertTrue(l.awaitEvent(SUBRESOURCE_ADDED));
		l.setExpectedChangedResource(element);

		list.remove(element);
		assertTrue(l.awaitEvent(SUBRESOURCE_REMOVED));
	}

	@Test
	public void virtualResourceListIsCreatable() {
		room = resMan.createResource("room" + counter++, Room.class);
		final ResourceList<WorkPlace> places = room.workPlaces();
		assertNotNull(places);
		assertFalse(places.exists());
		assertEquals(ResourceList.class, places.getResourceType());
		assertEquals(WorkPlace.class, places.getElementType());
		places.create();
		assertTrue(places.exists());
		assertEquals(ResourceList.class, places.getResourceType());
		assertEquals(WorkPlace.class, places.getElementType());
	}

	@Test
	public void canAddElementsToVirtualResourceList() {
		room = resMan.createResource("room" + counter++, Room.class);
		final ResourceList<WorkPlace> places = room.workPlaces();

		WorkPlace wp = places.add();
		WorkPlace wp2 = places.add();
		assertNotNull(wp);
		assertFalse(wp.exists());
		assertFalse(places.exists());

		wp.create();
		assertTrue(places.exists());
		assertTrue(wp.exists());
		assertFalse(wp2.exists());

		WorkPlace wp3 = places.add();
		assertTrue(wp3.exists());
	}

	@Test
	public void removeWorksForDirectSubresources() {
		room = resMan.createResource(newResourceName(), Room.class);
		final ResourceList<WorkPlace> wps = room.workPlaces();
		wps.create();

		WorkPlace el = wps.add();
		assertEquals(1, wps.size());
		assertTrue(wps.getAllElements().contains(el));

		wps.remove(el);
		assertEquals(0, wps.size());
		assertFalse(wps.getAllElements().contains(el));
	}

	@Test
	public void deleteOnElementWorks() {
		room = resMan.createResource(newResourceName(), Room.class);
		final ResourceList<WorkPlace> wps = room.workPlaces();
		wps.create();

		WorkPlace el = wps.add();
		assertEquals(1, wps.size());
		assertTrue(el.exists());
		assertTrue(wps.getAllElements().contains(el));

		el.delete();
		assertEquals(0, wps.size());
		assertFalse(wps.getAllElements().contains(el));
	}

	@Test
	public void deletingAReferenceElementShowsUpInList() {
		room = resMan.createResource(newResourceName(), Room.class);
		final ResourceList<WorkPlace> wps = room.workPlaces();
		wps.create();

		WorkPlace wp = resMan.createResource(newResourceName(), WorkPlace.class);
		wps.add(wp);

		assertEquals("list should contain 1 element", 1, wps.size());
		wp.delete();
		//assertEquals("list should be empty", 0, wps.size());
		assertEquals("list should be empty", 0, room.workPlaces().size());

	}

	@Test
    public void addedElementsRetainOrder() {
        @SuppressWarnings("unchecked")
        ResourceList<StringResource> strings = resMan.createResource(newResourceName(), ResourceList.class);
        strings.setElementType(StringResource.class);
        
        List<String> values = new ArrayList<>(Arrays.asList("3", "1", "2", "4"));
        
        StringResource sv = resMan.createResource(newResourceName(), StringResource.class);
        sv.setValue("3");
        strings.add(sv);
        
        sv = resMan.createResource(newResourceName(), StringResource.class);
        sv.setValue("1");
        strings.add(sv);
        
        sv = resMan.createResource(newResourceName(), StringResource.class);
        sv.setValue("2");
        strings.add(sv);
        
        sv = resMan.createResource(newResourceName(), StringResource.class);
        sv.setValue("4");
        strings.add(sv);
        
        for (int i = 0; i < values.size(); i++){
            assertEquals(values.get(i), strings.getAllElements().get(i).getValue());
        }
        
        values.add("6");
        strings.add().setValue("6");
        
        values.add("8");
        strings.add().setValue("8");
        
        values.add("5");
        strings.add().setValue("5");
        
        values.add("7");
        strings.add().setValue("7");
        
        for (int i = 0; i < values.size(); i++){
            assertEquals(values.get(i), strings.getAllElements().get(i).getValue());
        }
    }

	@Test
	public void addingReferencesWithSameNameWorks() {
		OnOffSwitch sw1 = resMan.createResource(newResourceName(), OnOffSwitch.class);
		OnOffSwitch sw2 = resMan.createResource(newResourceName(), OnOffSwitch.class);

		@SuppressWarnings("unchecked")
		ResourceList<BooleanResource> stateList = resMan.createResource(newResourceName(), ResourceList.class);
		stateList.setElementType(BooleanResource.class);

		stateList.add(sw1.stateControl().<BooleanResource> create());
		stateList.add(sw2.stateControl().<BooleanResource> create());

		assertEquals(2, stateList.size());
		System.out.println(stateList.getAllElements());
	}

	@Test
	public void changesToResourceListsAreVisibleThroughReferences() {
		Room room1 = resMan.createResource(newResourceName(), Room.class);
		room1.workPlaces().create();

		Room room2 = resMan.createResource(newResourceName(), Room.class);
		room2.workPlaces().setAsReference(room1.workPlaces());

		ResourceList<WorkPlace> l = room2.workPlaces();

		room1.workPlaces().add();
		assertEquals("", 1, room1.workPlaces().size());
		assertEquals("reference has changed", 1, room2.workPlaces().size());

		//ResourceList<WorkPlace> l = room2.workPlaces();

		assertTrue(l.isReference(false));
		assertEquals("reference has changed", 1, l.getAllElements().size());
		assertEquals("reference has changed", 1, l.size());
	}
    
    @Test
    public void valueListenerWorksOnListPath() throws InterruptedException {
        @SuppressWarnings("unchecked")
        ResourceList<ElectricityMeter> meterList = resMan.createResource(newResourceName(), ResourceList.class);
        meterList.setElementType(ElectricityMeter.class);
        ElectricityMeter mTop = resMan.createResource(newResourceName(), ElectricityMeter.class);
        mTop.powerReading().create();
        mTop.activate(true);
        
        ElectricityMeter mListEntry = meterList.add(mTop);
        ValueTestListener<PowerResource> l = new ValueTestListener<>(getApplicationManager());
        mListEntry.powerReading().addValueListener(l);
        //meterList.getAllElements().get(0).powerReading().addValueListener(l);
        //meterList.<ElectricityMeter>getSubResource(mListEntry.getName()).powerReading().addValueListener(l);
        mListEntry.powerReading().setValue(47.11f);
        //assertTrue(l.await());
        l.assertCallback();
    }
    
    @Test
    public void settingElementTypeRetrospectivelyWorks0() {
		final ResourceList<?> meterList = resMan.createResource(newResourceName(), ResourceList.class);
    	meterList.addDecorator("test",OnOffSwitch.class);
        meterList.setElementType(ElectricityMeter.class);
        Assert.assertEquals("Unexpected size of resource list",0, meterList.size()); 
        final List<?> list = meterList.getAllElements();
        Assert.assertEquals("Unexpected size of resource list entries",0, list.size());
        meterList.delete();
    }
    
    @Test
    public void settingElementTypeRetrospectivelyWorks1() {
    	@SuppressWarnings("unchecked")
		final ResourceList<ElectricityMeter> meterList = resMan.createResource(newResourceName(), ResourceList.class);
    	final ElectricityMeter sub = meterList.addDecorator("test", ElectricityMeter.class);
   		Assert.assertEquals(0, meterList.size()); // type not set
        meterList.setElementType(ElectricityMeter.class);
        Assert.assertEquals("Unexpected size of resource list",1, meterList.size()); 
        final List<ElectricityMeter> list = meterList.getAllElements();
        Assert.assertEquals("Unexpected size of resource list entries",1, list.size());
        ResourceAssertions.assertLocationsEqual(sub, list.get(0));
        meterList.delete();
    }
    
    @Test
    public void resourceListWorksAsReference1() {
    	final ElectricityMeter meter = resMan.createResource(newResourceName(), ElectricityMeter.class);
    	final ElectricityPrice price = resMan.createResource(newResourceName(), ElectricityPrice.class);
    	final String listName = "list";
    	final ResourceList<?> list = price.getSubResource(listName, ResourceList.class).create();
    	final OnOffSwitch switch0 = list.addDecorator("test", OnOffSwitch.class);
    	meter.price().setAsReference(price);
    	@SuppressWarnings("unchecked")
		final ResourceList<OnOffSwitch> listCopy = meter.price().getSubResource(listName, ResourceList.class);
    	listCopy.setElementType(OnOffSwitch.class);
    	Assert.assertEquals("Unexpected element type in resource list", OnOffSwitch.class, list.getElementType());
    	Assert.assertEquals("Unexpected resource list size", 1, listCopy.size());
    	Assert.assertEquals("Unexpected resource list size", 1, list.size());
    	final List<OnOffSwitch> switches = listCopy.getAllElements();
    	Assert.assertEquals("Unexpected resource list size", 1, switches.size());
    	ResourceAssertions.assertLocationsEqual(switch0, switches.get(0));
    	meter.delete();
    	price.delete();
    }
    
    @Test
    public void resourceListWorksAsReference2() {
    	final ElectricityMeter meter = resMan.createResource(newResourceName(), ElectricityMeter.class);
    	final ElectricityPrice price = resMan.createResource(newResourceName(), ElectricityPrice.class);
    	final ResourceList<?> list = resMan.createResource(newResourceName(), ResourceList.class);
    	final OnOffSwitch switch0 = list.addDecorator("test", OnOffSwitch.class);
    	@SuppressWarnings("unchecked")
		final ResourceList<OnOffSwitch> listCopy = (ResourceList<OnOffSwitch>) meter.addDecorator("list",list);
    	listCopy.setElementType(OnOffSwitch.class);
    	Assert.assertEquals("Unexpected element type in resource list", OnOffSwitch.class, list.getElementType());
    	Assert.assertEquals("Unexpected resource list size", 1, listCopy.size());
    	Assert.assertEquals("Unexpected resource list size", 1, list.size());
    	final List<OnOffSwitch> switches = listCopy.getAllElements();
    	Assert.assertEquals("Unexpected resource list size", 1, switches.size());
    	ResourceAssertions.assertLocationsEqual(switch0, switches.get(0));
    	meter.delete();
    	price.delete();
    }
    
}
