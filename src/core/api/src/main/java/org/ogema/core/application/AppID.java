/**
 * This file is part of OGEMA.
 *
 * OGEMA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * OGEMA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OGEMA. If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * 
 */
package org.ogema.core.application;

import java.net.URL;

import javax.servlet.http.HttpSession;

import org.ogema.core.security.AppPermissionType.AdminAction;
import org.osgi.framework.Bundle;

/**
 * This interface provides methods that help to identify the ogema application which is the owner of this AppID. It
 * supports a reference to the osgi context representation of the application too.
 */
public interface AppID {
	/**
	 * Get a unique string as an id for this application. Note: this is not invariant under restart of the framework,
	 * and it also changes when the application is removed and reinstalled. For an invariant app id, use the bundle
	 * symbolic name (see {@link #getBundle()}).
	 * 
	 * @return Id string of the owner application or null if any exception occurs.
	 */
	public String getIDString();

	/**
	 * Get the location identifier string of the application. This is equal to the applications bundle location
	 * identifier string.
	 * 
	 * @return Application location identifier string or null if any exception occurs.
	 */
	public String getLocation();

	/**
	 * Returns the bundle reference that contains this application.
	 * 
	 * @return Applications bundle reference
	 */
	public Bundle getBundle();

	/**
	 * Returns the application reference which is associated with the owner application of this AppID or null if the
	 * caller doesn't have the appropriate permission with {@link AdminAction#APP}.
	 * 
	 * @return Owners application reference.
	 */
	public Application getApplication();

	/**
	 * Gets the name of the owner user.
	 *
	 * @return the name string
	 */
	public String getOwnerUser();

	/**
	 * Gets the name of the group, the owner user is a member of it.
	 *
	 * @return the name string
	 */
	public String getOwnerGroup();

	/**
	 * Gets the version string of the app.
	 *
	 * @return the name string
	 */
	public String getVersion();

	public URL getOneTimePasswordInjector(String path, HttpSession ses);
}
