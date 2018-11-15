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
package org.ogema.restrictedimpl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.ogema.accesscontrol.ChannelPermission;
import org.ogema.accesscontrol.PermissionManager;
import org.ogema.accesscontrol.ResourcePermission;
import org.ogema.core.model.Resource;
import org.ogema.restricted.RestrictedAccess;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.log.LogService;

public class RestrictedAccessImpl implements BundleActivator, RestrictedAccess {

	private static String fileName = "./ogemauser";

	private PermissionManager pMan;
	LogService log;

	public void start(BundleContext bc) throws BundleException {
		/*
		 * Register a service to be user by a restricted app
		 */
		bc.registerService(RestrictedAccess.class.getName(), this, null);

		/*
		 * Get PermissionManager to delegate the permission checks
		 */
		pMan = (PermissionManager) bc.getService(bc.getServiceReference(PermissionManager.class.getName()));

		/*
		 * Log service
		 */
		ServiceReference<?> sRef = bc.getServiceReference(LogService.class.getName());
		log = (LogService) bc.getService(sRef);
	}

	public void stop(BundleContext context) {
		// logout();
	}

	/**
	 * How to check resource manager a ResourcePermission
	 */
	@Override
	public Object getResource(String path) {
		boolean check = false;
		try {
			if (pMan != null) {
				check = pMan.handleSecurity(new ResourcePermission(path, ResourcePermission.READ));
			}
		} catch (SecurityException e) {
			log(LogService.LOG_INFO, "ResourcePermission not granted to access to " + path);
			throw e;
		}
		if (check) {
			log(LogService.LOG_INFO, "ResourcePermission is granted to access to " + path);
		}

		// Do actions to prepare the return value.
		return null;
	}

	/**
	 * How to check resource manager a ResourceTypePermission
	 */
	@Override
	@SuppressWarnings("unchecked")
	public Object[] getResourcesOfType(String typename) {
		boolean check = false;
		Class<? extends Resource> cls = null;
		try {
			if (pMan != null) {
				cls = (Class<? extends Resource>) getClassPrivileged(typename);
			}
			check = pMan.handleSecurity(new ResourcePermission("*", cls, 0));
		} catch (SecurityException e) {
			log(LogService.LOG_INFO, "ResourcePermission not granted to access to resources of type " + typename);
			throw e;
		}
		if (check) {
			log(LogService.LOG_INFO, "ResourcePermission is granted to access to resources of type " + typename);
		}

		// Do actions to prepare the return value.
		return null;
	}

	private Class<?> getClassPrivileged(String typename) {
		Class<?> result = null;
		final String name = typename;
		result = AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
			public Class<?> run() {
				try {
					return Class.forName(name);
				} catch (ClassNotFoundException ioe) {
					ioe.printStackTrace();
				}
				return null;
			}
		});
		return result;
	}

	/**
	 * How to checks channel manager a ChannelPermission
	 */
	@Override
	public Object getChannel(String description) {
		boolean check = false;

		try {
			if (pMan != null) {
				check = pMan.handleSecurity(new ChannelPermission(description));
			}
		} catch (SecurityException e) {
			log(LogService.LOG_INFO, "ChannelPermission not granted to access to " + description);
			throw e;
		}
		if (check) {
			log(LogService.LOG_INFO, "ChannelPermission is granted to access to " + description);
		}

		// Do actions to prepare the return value.
		return null;
	}

	/**
	 * Check file access via privileged action. The caller doesn't need to have
	 * the appropriate file permission.
	 */
	@Override
	public void login(final String name) {
		final File f = new File(fileName);
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				if (f.exists()) {
					f.delete();
				}

				try {
					OutputStream os = new FileOutputStream(f);
					os.write(name.getBytes("UTF-8"));
					os.close();
					log(LogService.LOG_INFO, "User " + name + " logged in");
				} catch (IOException ioe) {
					log(LogService.LOG_WARNING, "Problem logging user in: " + ioe);
				}
				return null;
			}
		});
	}

	@Override
	public void logout() {
		final File f = new File(fileName);
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				if (!f.exists()) {
					throw new IllegalStateException("No user logged in");
				}

				f.delete();
				log(LogService.LOG_INFO, "User logged out");
				return null;
			}
		});
	}

	private void log(int level, String message) {
		if (log != null) {
			log.log(level, message);
		}
	}
}
