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
package org.ogema.core.administration;

import org.ogema.core.model.Resource;
import org.ogema.core.resourcemanager.ResourceDemandListener;

/** 
 * Representation of a resource demand registered by an application for administration purposes 
 */
public interface RegisteredResourceDemand {

	/** 
	 * Gets the administrator access to the application that registered the demand.
	 * @return admin access of registering application
	 */
	AdminApplication getApplication();

	/**
	 * Gets the resource type demanded.
	 * @return resource type of the demand
	 */
	Class<? extends Resource> getTypeDemanded();

	/**
	 * Gets the listener that is informed about new resources of the demanded type.
	 * @return the listener for this demand
	 */
	ResourceDemandListener<?> getListener();
}
