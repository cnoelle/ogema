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
package org.ogema.resourcemanager.impl;

import org.ogema.core.administration.AdminApplication;
import org.ogema.core.administration.RegisteredResourceListener;

import org.ogema.core.model.Resource;

/**
 * Represents a listener registration generated by a call to
 * {@link Resource#addResourceListener(org.ogema.core.resourcemanager.ResourceListener, boolean)}. The same
 * ResourceListenerRegistration object will be used in the {@link ElementInfo} of all affected Resources, ie. all sub
 * Resources of the Resource on which the listener was registered.
 * 
 * @author jlapp
 */
public interface ResourceListenerRegistration extends RegisteredResourceListener {

	public void queueResourceChangedEvent(Resource r, boolean valueChanged);

	public void performRegistration();

	public void unregister();

	@Override
	public Resource getResource();

	@Override
	public AdminApplication getApplication();

	@Override
	@SuppressWarnings("deprecation")
	public org.ogema.core.resourcemanager.ResourceListener getListener();

	public boolean isRecursive();

	/**
	 * @return the registration is actually no longer in use.
	 */
	public boolean isAbandoned();

}
