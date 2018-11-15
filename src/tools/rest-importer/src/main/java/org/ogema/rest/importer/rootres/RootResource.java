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
package org.ogema.rest.importer.rootres;

import java.util.List;

import org.ogema.core.application.ApplicationManager;
import org.ogema.core.model.Resource;
import org.ogema.core.resourcemanager.AccessMode;
import org.ogema.core.resourcemanager.AccessModeListener;
import org.ogema.core.resourcemanager.AccessPriority;
import org.ogema.core.resourcemanager.NoSuchResourceException;
import org.ogema.core.resourcemanager.ResourceAlreadyExistsException;
import org.ogema.core.resourcemanager.ResourceException;
import org.ogema.core.resourcemanager.ResourceStructureListener;
import org.ogema.core.resourcemanager.ResourceGraphException;
import org.ogema.core.resourcemanager.ResourceValueListener;
import org.ogema.core.resourcemanager.VirtualResourceException;

/**
 * 
 * @author jlapp
 */
public class RootResource implements Resource {

	final ApplicationManager appMan;

	public RootResource(ApplicationManager appMan) {
		this.appMan = appMan;
	}

	@Override
	public String getName() {
		return "";
	}

	@Override
	public String getPath(String delimiter) {
		return "/";
	}

	@Override
	public String getLocation(String delimiter) {
		return "/";
	}

	@Override
	public Class<? extends Resource> getResourceType() {
		return getClass();
	}

	@Override
	@Deprecated
	public void addResourceListener(org.ogema.core.resourcemanager.ResourceListener listener, boolean recursive) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	@Deprecated
	public boolean removeResourceListener(org.ogema.core.resourcemanager.ResourceListener listener) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void addValueListener(ResourceValueListener<?> listener) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void addValueListener(ResourceValueListener<?> listener, boolean callOnEveryUpdate) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean removeValueListener(ResourceValueListener<?> listener) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean isActive() {
		return true;
	}

	@Override
	public boolean isTopLevel() {
		return false;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends Resource> T getParent() {
		return (T) this;
	}

	@Override
	public List<Resource> getSubResources(boolean recursive) {
		if (recursive) {
			throw new UnsupportedOperationException();
		}
		return appMan.getResourceAccess().getToplevelResources(Resource.class);
	}

	@Override
	public List<Resource> getDirectSubResources(boolean recursive) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean isReference(boolean recursive) {
		return false;
	}

	@Override
	public <T extends Resource> T getSubResource(String name) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void activate(boolean recursive) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void deactivate(boolean recursive) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void setOptionalElement(String name, Resource newElement) throws NoSuchResourceException, ResourceException,
			ResourceGraphException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public Resource addOptionalElement(String name) throws NoSuchResourceException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T extends Resource> T addDecorator(String name, Class<T> resourceType)
			throws ResourceAlreadyExistsException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T extends Resource> T addDecorator(String name, T decoratingResource)
			throws ResourceAlreadyExistsException, NoSuchResourceException, ResourceGraphException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void deleteElement(String name) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean equalsLocation(Resource other) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean equalsPath(Resource resource) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T extends Resource> List<T> getReferencingResources(Class<T> parentType) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T extends Resource> List<T> getSubResources(Class<T> resourceType, boolean recursive) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	final public String getPath() {
		return getPath("/");
	}

	@Override
	final public String getLocation() {
		return getLocation("/");
	}

	@Override
	public <T extends Resource> T getSubResource(String name, Class<T> type) throws NoSuchResourceException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T extends Resource> T setAsReference(T reference) throws NoSuchResourceException, ResourceException,
			ResourceGraphException, VirtualResourceException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T extends Resource> T create() throws ResourceAlreadyExistsException, NoSuchResourceException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean exists() {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void delete() {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void addStructureListener(ResourceStructureListener listener) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean removeStructureListener(ResourceStructureListener listener) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean isWriteable() {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public boolean isDecorator() {
		return false;
	}

	@Override
	public AccessMode getAccessMode() {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public void addAccessModeListener(AccessModeListener listener) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public boolean removeAccessModeListener(AccessModeListener listener) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public boolean requestAccessMode(AccessMode accessMode, AccessPriority priority) throws SecurityException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public AccessPriority getAccessPriority() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T extends Resource> T getLocationResource() {
		return (T) this;
	}

	@Override
	public List<Resource> getReferencingNodes(boolean transitive) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

}
