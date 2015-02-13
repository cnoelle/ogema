/**
 * This file is part of OGEMA.
 *
 * OGEMA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OGEMA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OGEMA. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ogema.resourcemanager.impl;

import java.lang.ref.WeakReference;
import java.util.concurrent.Callable;
import org.ogema.core.administration.AdminApplication;
import org.ogema.core.administration.RegisteredResourceListener;
import org.ogema.core.application.ApplicationManager;

import org.ogema.core.model.Resource;
import org.ogema.core.resourcemanager.ResourceListener;
import org.ogema.resourcetree.TreeElement;

/**
 * Represents a listener registration generated by a call to
 * {@link Resource#addResourceListener(org.ogema.core.resourcemanager.ResourceListener)}. The same
 * ResourceListenerRegistration object will be used in the {@link ElementInfo} of all affected Resources, ie. all sub
 * Resources of the Resource on which the listener was registered.
 * 
 * @author jlapp
 */
public interface ResourceListenerRegistration extends RegisteredResourceListener {

	public void queueResourceChangedEvent(Resource r, boolean valueChanged);

	public void performRegistration();

	public void unregister();

	public Resource getResource();

	public AdminApplication getApplication();

	public ResourceListener getListener();

	public boolean isRecursive();

	/**
	 * @return the registration is actually no longer in use.
	 */
	public boolean isAbandoned();

}