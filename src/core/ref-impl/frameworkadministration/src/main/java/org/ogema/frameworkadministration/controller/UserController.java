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
package org.ogema.frameworkadministration.controller;

import java.io.IOException;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ogema.accesscontrol.AccessManager;
import org.ogema.accesscontrol.AppPermissionFilter;
import org.ogema.accesscontrol.PermissionManager;
import org.ogema.accesscontrol.ResourcePermission;
import org.ogema.core.administration.AdminApplication;
import org.ogema.core.administration.AdministrationManager;
import org.ogema.core.application.AppID;
import org.ogema.core.application.ApplicationManager;
import org.ogema.core.security.AppPermission;
import org.ogema.core.security.AppPermissionType;
import org.ogema.frameworkadministration.FrameworkAdministration;
import org.ogema.frameworkadministration.json.UserJsonAppId;
import org.ogema.frameworkadministration.json.UserJsonAppIdList;
import org.ogema.frameworkadministration.json.UserJsonCondition;
import org.ogema.frameworkadministration.json.UserJsonPermission;
import org.ogema.frameworkadministration.json.UserJsonPermissionCondition;
import org.ogema.frameworkadministration.json.UserJsonPermittedApps;
import org.ogema.frameworkadministration.json.UserJsonPoliciesList;
import org.ogema.frameworkadministration.json.UserJsonResourcePolicy;
import org.ogema.frameworkadministration.json.UserJsonResourcePolicyList;
import org.ogema.frameworkadministration.json.get.UserInformationJsonGet;
import org.ogema.frameworkadministration.json.get.UserJsonGet;
import org.ogema.frameworkadministration.json.get.UserJsonGetList;
import org.ogema.frameworkadministration.json.post.UserJsonChangePassword;
import org.ogema.frameworkadministration.json.post.UserJsonCopyUser;
import org.ogema.frameworkadministration.json.post.UserJsonCreateUser;
import org.ogema.frameworkadministration.json.post.UserJsonDeleteUser;
import org.ogema.frameworkadministration.utils.Utils;
import org.osgi.framework.Version;
import org.osgi.service.condpermadmin.ConditionInfo;
import org.osgi.service.condpermadmin.ConditionalPermissionInfo;
import org.osgi.service.permissionadmin.PermissionInfo;
import org.osgi.service.useradmin.User;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *
 * @author tgries
 */
public class UserController {

	public static UserController instance = null;
	private AccessManager accessManager;
	private PermissionManager permissionManager;
	private AdministrationManager administrationManager;
	private ApplicationManager appManager;

	public ApplicationManager getAppManager() {
		return appManager;
	}

	public void setAppManager(ApplicationManager appManager) {
		this.appManager = appManager;
	}

	public AdministrationManager getAdministrationManager() {
		return administrationManager;
	}

	public void setAdministrationManager(AdministrationManager administrationManager) {
		this.administrationManager = administrationManager;
	}

	public PermissionManager getPermissionManager() {
		return permissionManager;
	}

	public void setPermissionManager(PermissionManager permissionManager) {
		this.permissionManager = permissionManager;
	}

	public static UserController getInstance() {
		if (instance == null) {
			instance = new UserController();
		}
		return instance;
	}

	private UserController() {
	}

	/**
	 * Checks if the given user has administrator rights. master always returns true. Machine users always return false.
	 * Checks for ALL APPS role and java.security.AllPermission policy.
	 * 
	 * @param user
	 *            the name of the user as string
	 * @return true or false
	 */
	public boolean checkUserAdmin(String user) {

		if ("master".equals(user)) {
			return true;
		}

		// machine user is not allowed to be admin
		if (!accessManager.isNatural(user)) {
			return false;
		}

		// The permission "ALL APPS" doesn't longer exist
		// List<String> appList = accessManager.getAppsPermitted(user);
		// if (appList != null && appList.contains("ALL APPS")) {
		// //first criteria met
		//
		String allPerms = Utils.USER_ALLPERMISSION;
		AppPermission appPermission = accessManager.getPolicies(user);
		Map<String, ConditionalPermissionInfo> grantedPerms = appPermission.getGrantedPerms();
		for (ConditionalPermissionInfo cpi : grantedPerms.values()) {
			PermissionInfo[] permInfo = cpi.getPermissionInfos();
			for (PermissionInfo pi : permInfo) {
				if (allPerms.equals(pi.getType())) {
					return true;
				}
			}
		}
		// }

		return false;
	}

	/**
	 * Grants administrator rights to a given user. Only natural user are allowed to be administrators. Adds ALL APPS as
	 * a role and puts java.security.AllPermission into policies.
	 * 
	 * @param user
	 *            the name of the user as string
	 * @return true on success otherwise false
	 */
	public boolean grantAdminRights(String user) {

		// master is always admin
		if ("master".equals(user)) {
			return false;
		}

		// machine user should not be admin
		if (!accessManager.isNatural(user)) {
			return false;
		}

		AppPermission appPermission = accessManager.getPolicies(user);
		String permName = Utils.USER_ALLPERMISSION;

		appPermission.addPermission(permName, null, null);
		permissionManager.installPerms(appPermission);

		// There is no need to any addition to AllPermission, because AllPermission implies any WebAccessPermission
		// accessManager.addPermission(user, "ALL APPS");
		// accessManager.addPermission(user, AppPermissionFilter.ALLAPPSPERMISSION);

		return true;
	}

	/**
	 * Revokes administrator rights to a given user. It is not allowed to remove the rights for the master user. Removed
	 * ALL APPS role and adds NO APPS as a new role. Removes java.security.AllPermission policy.
	 * 
	 * @param user
	 *            the name of the user as string
	 * @return true on success otherwise false
	 */
	public boolean revokeAdminRights(String user) {

		if ("master".equals(user)) {
			return false;
		}

		// machine user should never be admin in the first place
		if (!accessManager.isNatural(user)) {
			return false;
		}

		AppPermission appPermission = accessManager.getPolicies(user);
		String allPerms = Utils.USER_ALLPERMISSION;

		String permissionName;

		Map<String, ConditionalPermissionInfo> grantedPerms = appPermission.getGrantedPerms();
		for (ConditionalPermissionInfo cpi : grantedPerms.values()) {
			PermissionInfo[] permInfo = cpi.getPermissionInfos();
			for (PermissionInfo pi : permInfo) {
				if (allPerms.equals(pi.getType())) {
					if (cpi.getName() != null) {
						permissionName = cpi.getName();
						appPermission.removePermission(permissionName);
					}
				}
			}
		}

		permissionManager.installPerms(appPermission);

		// removePermissionRole(user, "ALL APPS");
		// accessManager.addPermission(user, "NO APPS");

		return true;

	}

	// private void removePermissionRole(String user, String role) {
	//
	// Role usrRole = userAdmin.getRole(user);
	//
	// if ("NO APPS".equals(role) || "ALL APPS".equals(role)) {
	// Group roleGroup = (Group) userAdmin.getRole(role);
	// roleGroup.removeMember(usrRole);
	// }
	// }

	/**
	 * Sets the allowed applications with registered webresources. Does also remove applications from the list. It
	 * possible to add or remove a permission even if the application has no webresources.
	 * 
	 * @param jsonMessage
	 *            message in json format. See {@link org.ogema.frameworkadministration.json.UserJsonAppIdList} for
	 *            message format.
	 * @return true on success, otherwise false
	 */
	public boolean setAppsNaturalUser(String jsonMessage) {

		UserJsonAppIdList appIDList;

		ObjectMapper mapper = new ObjectMapper();
		try {
			appIDList = mapper.readValue(jsonMessage, UserJsonAppIdList.class);
		} catch (IOException ex) {
			Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			return false;
		}

		String user = appIDList.getUser();
		String role = appIDList.getRole();
		List<UserJsonAppId> apps = appIDList.getApps();

		for (UserJsonAppId singleApp : apps) {

			boolean permitted = singleApp.isPermitted();
			String appIdString = singleApp.getAppID();

			if ("ALL APPS".equals(role)) {
				accessManager.addPermission(user, AppPermissionFilter.ALLAPPSPERMISSION);
				// accessManager.addPermission(user, appIdString);
				continue; // FIXME Break the loop because after all apps permission is granted other perms don't any
				// further effect
			}

			AppID appID = findAppIdForString(appIdString);
			AppPermissionFilter props = new AppPermissionFilter(appID.getBundle().getSymbolicName(), "*", "*",
					Version.emptyVersion
							.toString()/* appID.getOwnerUser(), appID.getOwnerGroup(), appID.getVersion() */);
			if (permitted) {

				accessManager.addPermission(user, props);
			}
			else {
				accessManager.removePermission(user, props);
			}

			// if ("NO APPS".equals(role)) {
			// accessManager.addPermission(user, "NO APPS");
			// accessManager.removePermission(user, appID);

			// }
		}
		return true;
	}

	/**
	 * finds a AppId for a given AppId string
	 * 
	 * @param appIdString
	 *            OGEMA AppId string
	 * @return AppID object or null
	 */
	private AppID findAppIdForString(String appIdString) {

		List<AdminApplication> list = administrationManager.getAllApps();
		for (AdminApplication app : list) {
			if (app.getID().getIDString().equals(appIdString)) {
				return app.getID();
			}
		}

		return null;
	}

	/**
	 * Generates a list of all applications for a natural user.
	 * 
	 * @param user
	 *            the name of the user as string
	 * @return A list in json format of all natural apps. See
	 *         {@link org.ogema.frameworkadministration.json.UserJsonAppIdList} for message format. Returns an error
	 *         message if user is not a natural user
	 */
	public String getAppsNaturalUser(String user) {

		String result = "{}";

		if (!accessManager.isNatural(user)) {
			return Utils.createMessage("ERROR", user + " ist not a natural user");
		}

		// List<String> list = accessManager.getAppsPermitted(user);
		// if (list == null) {
		// list = Collections.emptyList();
		// }
		List<AdminApplication> appList = administrationManager.getAllApps();

		UserJsonAppIdList userAppListJson = new UserJsonAppIdList();
		userAppListJson.setUser(user);

		// if (list.contains("ALL APPS")) {
		if (accessManager.isAllAppsPermitted(user)) {
			userAppListJson.setRole("ALL APPS");
		}
		// else if (list.contains("NO APPS")) {
		else if (accessManager.isNoAppPermitted(user)) {
			userAppListJson.setRole("NO APPS");
		}
		else {
			userAppListJson.setRole(null);
		}

		for (AdminApplication app : appList) {
			AppID appID = app.getID();
			String appIDString = app.getID().getIDString();
			Long bundleID = app.getBundleRef().getBundleId();

			boolean needFilter = false;
			for (String filter : Utils.FILTERED_USERAPPS) {
				if (appIDString.contains(filter)) {
					needFilter = true;
					break;
				}
			}
			if (needFilter) {
				continue;
			}

//			@SuppressWarnings("deprecation")
//			Map<String, String> registeredResources = appManager.getWebAccessManager().getRegisteredResources(appID);
			final Map<String, String> registeredResources = app.getWebAccess().getRegisteredResources();
			if ((registeredResources == null || registeredResources.isEmpty()) && app.getWebAccess().getStartUrl() == null) {
				continue;
			}

			UserJsonAppId singleAppJson = new UserJsonAppId();
			singleAppJson.setAppID(appIDString);
			singleAppJson.setReadableName(appID.getBundle().getSymbolicName());
			singleAppJson.setBundleID(bundleID);

			if (accessManager.isAllAppsPermitted(user)) {
				singleAppJson.setPermitted(true);
			}
			else if (accessManager.isNoAppPermitted(user)) {
				singleAppJson.setPermitted(false);
			}
			else if (accessManager.isAppPermitted(user, appID)) {
				singleAppJson.setPermitted(true);
			}
			else {
				singleAppJson.setPermitted(false);
			}

			userAppListJson.getApps().add(singleAppJson);
		}

		ObjectMapper mapper = new ObjectMapper();
		try {
			result = mapper.writeValueAsString(userAppListJson);
		} catch (IOException ex) {
			ex.printStackTrace();
			result = "{}";
		}

		return result;
	}

	/**
	 * Generates a list of all resource policies for a machine user or administrator.
	 * 
	 * @param user
	 *            the name of the user as string
	 * @return A list in json format of all resource policies. See
	 *         {@link org.ogema.frameworkadministration.json.UserJsonResourcePolicyList} for message format. Returns an
	 *         error message if the user is not a machine user except administrators.
	 */
	public String getPoliciesMachineUser(String user) {

		String result = "{}";

		if (accessManager.isNatural(user) && !checkUserAdmin(user)) {
			return Utils.createMessage("ERROR", user + " is not a machine user");
		}

		AppPermission appPermission = accessManager.getPolicies(user);
		Map<String, ConditionalPermissionInfo> grantedPermsMap = appPermission.getGrantedPerms();

		UserJsonResourcePolicyList userPolicyList = new UserJsonResourcePolicyList();
		userPolicyList.setUser(user);

		for (String s : grantedPermsMap.keySet()) {

			ConditionalPermissionInfo cond = grantedPermsMap.get(s);

			@SuppressWarnings("unused")
			ConditionInfo[] conditionInfoArray = cond.getConditionInfos();
			PermissionInfo[] permissionInfoArray = cond.getPermissionInfos();

			for (PermissionInfo pi : permissionInfoArray) {

				String permissionName = pi.getType(); // org.ogema.accesscontrol.ResourcePermission
				if (!permissionName.equals(ResourcePermission.class.getName()))
					continue;
				String uniqueName = cond.getName();
				String resourcePathType = pi.getName(); // path=...,type=...

				String resourcePath = null;
				String resourceType = null;

				if (resourcePathType.contains(",")) {
					String[] split = resourcePathType.split(",");
					for (String pathOrType : split) {
						if (pathOrType.contains("path=")) {
							resourcePath = pathOrType;
						}
						else if (pathOrType.contains("type=")) {
							resourceType = pathOrType;
						}
					}
				}
				else {
					if (resourcePathType.contains("path=")) {
						resourcePath = resourcePathType;
					}
					else if (resourcePathType.contains("type=")) {
						resourceType = resourcePathType;
					}
				}

				String permissionActions = pi.getActions(); // allow or deny
				String accessDecision = cond.getAccessDecision(); // read,write,...

				if (!Utils.USER_PERMISSIONAME.equals(permissionName)) {
					continue;
				}

				UserJsonResourcePolicy userPerms = new UserJsonResourcePolicy();
				userPerms.setPermissionName(permissionName);
				userPerms.setAccessDecision(accessDecision);
				userPerms.setResourcePath(resourcePath);
				userPerms.setPermissionActions(permissionActions);
				userPerms.setResourceType(resourceType);
				userPerms.setUniqueName(uniqueName);

				userPolicyList.getResourcePermissions().add(userPerms);

			}

		}

		ObjectMapper mapper = new ObjectMapper();
		try {
			result = mapper.writeValueAsString(userPolicyList);
		} catch (IOException ex) {
			Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			result = "{}";
		}

		return result;

	}

	/**
	 * Sets new policies for a given user. The user is part of the json message. This method does not differ between
	 * machine or natural user.
	 * 
	 * @param jsonMessage
	 *            Resource Policies for an user in json format. See
	 *            {@link org.ogema.frameworkadministration.json.UserJsonResourcePolicyList} for message format.
	 * @return true on success, otherwise false
	 */
	public boolean setPoliciesMachineUser(String jsonMessage) {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonResourcePolicyList userResourcePolicies;

		try {
			userResourcePolicies = mapper.readValue(jsonMessage, UserJsonResourcePolicyList.class);
		} catch (IOException ex) {
			Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			return false;
		}

		String user = userResourcePolicies.getUser();
		List<UserJsonResourcePolicy> policyList = userResourcePolicies.getResourcePermissions();
		AppPermission appPermission = accessManager.getPolicies(user);

		for (UserJsonResourcePolicy policy : policyList) {
			String accessDecision = policy.getAccessDecision();
			String path = policy.getResourcePath();
			String type = policy.getResourceType();
			String uniqueName = policy.getUniqueName();

			if (uniqueName != null) {
				appPermission.removePermission(uniqueName);
			}

			if (policy.isDelete()) {
				continue;
			}

			StringBuilder pathTypeBuffer = new StringBuilder();

			if (path != null) {
				if (!path.startsWith("path=")) {
					path = "path=" + path;
				}
				pathTypeBuffer.append(path);
			}
			if (type != null) {
				if (!type.startsWith("type=")) {
					type = "type=" + type;
				}
				if (pathTypeBuffer.length() > 0) {
					pathTypeBuffer.append(",");
				}
				pathTypeBuffer.append(type);
			}

			String pathAndType = pathTypeBuffer.toString();

			String actions = policy.getPermissionActions();

			String conditionType = Utils.USER_CONDITIONINFOTYPE;
			String[] args = { (Utils.USER_PRECONDITIONFILE + user) };
			ConditionInfo conditionInfo = new ConditionInfo(conditionType, args);

			// String permName = Utils.USER_PERMISSIONTYPE;
			String permName = policy.getPermissionName();
			String arguments[] = { pathAndType, actions };

			// only simple permissions, option with condition is implemented
			if (accessDecision.toLowerCase().equals("allow")) {
				appPermission.addPermission(permName, arguments, conditionInfo);
			}
			else if (accessDecision.toLowerCase().equals("deny")) {
				appPermission.addException(permName, arguments, conditionInfo);
			}
		}

		permissionManager.installPerms(appPermission);

		return true;
	}

	public String getPermittedApps(String user) {

		String result = "{}";
		List<AppID> list = accessManager.getAppsPermitted(user);
		ObjectMapper mapper = new ObjectMapper();

		UserJsonPermittedApps userPermittedApps = new UserJsonPermittedApps();
		userPermittedApps.setUser(user);
		if (list == null) {
			list = Collections.emptyList();
		}
		userPermittedApps.setPermittedApps(list);

		try {
			result = mapper.writeValueAsString(userPermittedApps);
		} catch (IOException ex) {
			Logger.getLogger(FrameworkAdministration.class.getName()).log(Level.SEVERE, null, ex);
		}

		return result;
	}

	public boolean setPermittedApps(String permittedApps) {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonPermittedApps userPermittedApps;
		try {
			userPermittedApps = mapper.readValue(permittedApps, UserJsonPermittedApps.class);
		} catch (IOException ex) {
			Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			return false;
		}

		String user = userPermittedApps.getUser();
		List<AppID> permittedAppList = userPermittedApps.getPermittedApps();

		for (AppID singlePermittedApp : permittedAppList) {
			AppPermissionFilter filter = new AppPermissionFilter(singlePermittedApp.getBundle().getSymbolicName(),
					singlePermittedApp.getOwnerGroup(), singlePermittedApp.getOwnerUser(),
					singlePermittedApp.getVersion());
			accessManager.addPermission(user, filter);
		}

		return true;
	}

	public boolean removePermittedApps(String unPermittedApps) {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonPermittedApps userUnPermittedApps;

		try {
			userUnPermittedApps = mapper.readValue(unPermittedApps, UserJsonPermittedApps.class);
		} catch (IOException ex) {
			Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			return false;
		}

		String user = userUnPermittedApps.getUser();
		List<AppID> unPermittedAppList = userUnPermittedApps.getPermittedApps();

		for (AppID singleUnPermittedApp : unPermittedAppList) {
			AppPermissionFilter filter = new AppPermissionFilter(singleUnPermittedApp.getBundle().getSymbolicName(),
					singleUnPermittedApp.getOwnerGroup(), singleUnPermittedApp.getOwnerUser(),
					singleUnPermittedApp.getVersion());
			accessManager.removePermission(user, filter);
		}

		return true;
	}

	public boolean setPolicies(String policies) {

		UserJsonPoliciesList userPoliciesList;

		ObjectMapper mapper = new ObjectMapper();

		try {
			userPoliciesList = mapper.readValue(policies, UserJsonPoliciesList.class);
		} catch (IOException ex) {
			Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			return false;
		}

		if (userPoliciesList != null) {

			String user = userPoliciesList.getUser();
			AppPermission appPermission = accessManager.getPolicies(user);

			List<UserJsonPermissionCondition> permsAndCond = userPoliciesList.getPermissionsAndCondition();
			for (UserJsonPermissionCondition upc : permsAndCond) {
				UserJsonCondition userCondition = upc.getCondition();
				ConditionInfo conditionInfo = null;
				if (userCondition != null) {
					String conditionType = userCondition.getType();
					String[] args = { userCondition.getFile() };
					conditionInfo = new ConditionInfo(conditionType, args);
				}
				String mode = upc.getMode();
				String readableName = upc.getName();

				boolean needFilter = false;
				for (String filter : Utils.FILTERED_PERMISSIONS) {
					if (readableName.contains(filter)) {
						needFilter = true;
						break;
					}
				}
				if (needFilter) {
					continue;
				}

				List<UserJsonPermission> userPermissions = upc.getPermissions();
				for (UserJsonPermission up : userPermissions) {
					String permName = up.getPermissionName();
					String resourcePath = up.getResourcePath();
					String actions = up.getActions();
					String args[] = { resourcePath, actions };

					// only simple permissions, option with condition is implemented
					if (mode.toLowerCase().equals("allow")) {
						appPermission.addPermission(permName, args, conditionInfo);
					}
					else if (mode.toLowerCase().equals("deny")) {
						appPermission.addException(permName, args, conditionInfo);
					}
				}

			}
			permissionManager.installPerms(appPermission);
		}

		return true;
	}

	public String getPolicies(String user) {

		String result = "{}";

		ObjectMapper mapper = new ObjectMapper();

		UserJsonPoliciesList userPolicesList = new UserJsonPoliciesList();
		userPolicesList.setUser(user);

		AppPermission appPermission = accessManager.getPolicies(user);
		Map<String, ConditionalPermissionInfo> grantedPermsMap = appPermission.getGrantedPerms();

		// allow policies
		for (String s : grantedPermsMap.keySet()) {
			ConditionalPermissionInfo cpi = grantedPermsMap.get(s);
			UserJsonPermissionCondition userPermCond = addPermissionsAndCondition(cpi);
			userPolicesList.getPermissionsAndCondition().add(userPermCond);
		}

		// deny policies
		List<AppPermissionType> exceptionsList = appPermission.getExceptions();

		for (AppPermissionType apt : exceptionsList) {
			ConditionalPermissionInfo cpi = apt.getDeclarationInfo();
			UserJsonPermissionCondition userPermCond = addPermissionsAndCondition(cpi);
			userPolicesList.getPermissionsAndCondition().add(userPermCond);
		}

		try {
			result = mapper.writeValueAsString(userPolicesList);
		} catch (IOException ex) {
			Logger.getLogger(FrameworkAdministration.class.getName()).log(Level.SEVERE, null, ex);
		}

		return result;
	}

	private UserJsonPermissionCondition addPermissionsAndCondition(ConditionalPermissionInfo cpi) {

		UserJsonPermissionCondition userPermCond = new UserJsonPermissionCondition();

		String accessDecision = cpi.getAccessDecision(); // allow, deny
		userPermCond.setMode(accessDecision);

		String name = cpi.getName(); // urps, basic import rights ogema
		userPermCond.setName(name);

		ConditionInfo[] conditionInfoArray = cpi.getConditionInfos();
		PermissionInfo[] permissionInfoArray = cpi.getPermissionInfos();

		// if there is a conditionInformation

		if (conditionInfoArray.length > 0) {
			ConditionInfo conditionInfo = conditionInfoArray[0];
			String type = conditionInfo.getType();
			String[] args = conditionInfo.getArgs();
			if (args.length > 0) {
				String file = args[0];
				UserJsonCondition userJsonCond = new UserJsonCondition();
				userJsonCond.setType(type);
				userJsonCond.setFile(file);
				userPermCond.setCondition(userJsonCond);
			}
		}

		for (PermissionInfo pi : permissionInfoArray) {

			UserJsonPermission singlePermission = new UserJsonPermission();

			String permissionName = pi.getType();
			String resourcePath = pi.getName();
			String actions = pi.getActions();

			singlePermission.setPermissionName(permissionName);
			singlePermission.setResourcePath(resourcePath);
			singlePermission.setActions(actions);

			userPermCond.getPermissions().add(singlePermission);

		}

		return userPermCond;
	}

	/**
	 * Delete an user defined in the json message.
	 * 
	 * @param jsonMessage
	 *            See {@link org.ogema.frameworkadministration.json.post.UserJsonDeleteUser}
	 * @return true on success, otherwise false
	 * @throws IOException
	 */
	public boolean deleteUser(String jsonMessage) throws IOException {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonDeleteUser deleteUser = mapper.readValue(jsonMessage, UserJsonDeleteUser.class);

		String user = deleteUser.getUser();

		if (!accessManager.getAllUsers().contains(user)) {
			return false;
		}

		accessManager.removeUser(user);

		return true;
	}

	/**
	 * Create an user defined in the json message.
	 * 
	 * @param jsonMessage
	 *            See {@link org.ogema.frameworkadministration.json.post.UserJsonCreateUser}
	 * @return true on success, otherwise false
	 * @throws IOException
	 */
	public boolean createUser(String jsonMessage) throws IOException {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonCreateUser newUser = mapper.readValue(jsonMessage, UserJsonCreateUser.class);

		String user = newUser.getUser();
		boolean isNatural = newUser.isIsNatural();
		String pwd = newUser.getPwd();

		if (accessManager.getAllUsers().contains(user)) {
			return false;
		}

		accessManager.createUser(user, pwd, isNatural);
		// accessManager.setNewPassword(user, pwd);
		return true;
	}

	/**
	 * Changes the password for an user defined in the json message.
	 * 
	 * @param jsonMessage
	 *            see {@link org.ogema.frameworkadministration.json.post.UserJsonChangePassword}
	 * @return true on success, otherwise false
	 * @throws IOException
	 */
	public boolean changePassword(String jsonMessage) throws IOException {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonChangePassword userPwd = mapper.readValue(jsonMessage, UserJsonChangePassword.class);
		String user = userPwd.getUser();
		String pwd = userPwd.getPwd();
		String oldpwd = userPwd.getoldpwd();

		// FIXME the old password should be a part of the jsonMessage -> throws exception if pw is wrong
		accessManager.setNewPassword(user, oldpwd, pwd); // FIXME in some implementations this throws an exception
		// in others it simply returns if the old pw does not match -> we throw an exception if the pw has not been changed 
		// to get a uniform response on the user page.
		if (!accessManager.authenticate(user, pwd, accessManager.isNatural(user)))
			throw new SecurityException("Wrong old password.");
		return true;
	}

	/**
	 * Copies the resource policies and webresource (permitted apps) to another user which will be created in the
	 * process. Differs between machine user, natural user and administrator.
	 * 
	 * @param jsonMessage
	 *            {@link org.ogema.frameworkadministration.json.post.UserJsonCopyUser}
	 * @return true on success, otherwise false
	 * @throws IOException
	 */
	public boolean copyUser(String jsonMessage) throws IOException {

		ObjectMapper mapper = new ObjectMapper();
		UserJsonCopyUser copyUser = mapper.readValue(jsonMessage, UserJsonCopyUser.class);

		String userNew = copyUser.getUserNew();
		String userOld = copyUser.getUserOld();
		String pwd = copyUser.getPwd();

		// check old user role
		boolean isNaturalOld = accessManager.isNatural(userOld);
		// get old user policies
		String oldPolicies = getPoliciesMachineUser(userOld);
		// get old user permitted apps
		String oldPermittedApps = getAppsNaturalUser(userOld);

		// create user
		UserJsonCreateUser createUser = new UserJsonCreateUser(userNew, isNaturalOld, pwd);

		String createUserMessage = mapper.writeValueAsString(createUser);
		createUser(createUserMessage);

		if (checkUserAdmin(userOld)) {
			grantAdminRights(userNew);
			return true;
		}

		if (!isNaturalOld) {
			// set new user policies
			UserJsonResourcePolicyList policies;
			try {
				policies = mapper.readValue(oldPolicies, UserJsonResourcePolicyList.class);
			} catch (IOException ex) {
				Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
				return false;
			}

			policies.setUser(userNew);

			String newPolicies = "{}";

			try {
				newPolicies = mapper.writeValueAsString(policies);
			} catch (IOException ex) {
				Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
				return false;
			}

			setPoliciesMachineUser(newPolicies);
		}

		if (isNaturalOld) {
			// set new user permitted apps
			UserJsonAppIdList permittedApps;
			try {
				permittedApps = mapper.readValue(oldPermittedApps, UserJsonAppIdList.class);
			} catch (IOException ex) {
				Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
				return false;
			}

			permittedApps.setUser(userNew);

			String newPermittedApps = "{}";

			try {
				newPermittedApps = mapper.writeValueAsString(permittedApps);
			} catch (IOException ex) {
				Logger.getLogger(UserController.class.getName()).log(Level.SEVERE, null, ex);
			}

			setAppsNaturalUser(newPermittedApps);
		}
		return true;
	}

	/**
	 * Generates a list of all user in a json format. See
	 * {@link org.ogema.frameworkadministration.json.get.UserJsonGetList} for message format.
	 * 
	 * @return a list of all users in json.
	 */
	public String getAllUsersJSON() {

		List<String> users = accessManager.getAllUsers();
		String result = "{}";

		UserJsonGetList userList = new UserJsonGetList();
		ObjectMapper mapper = new ObjectMapper();

		for (String name : users) {
			boolean isNatural = accessManager.isNatural(name);
			boolean isAdmin = checkUserAdmin(name);
			userList.getList().add(new UserJsonGet(name, isNatural, isAdmin));
		}

		try {
			result = mapper.writeValueAsString(userList);
		} catch (IOException ex) {
			Logger.getLogger(FrameworkAdministration.class.getName()).log(Level.SEVERE, null, ex);
		}

		return result;
	}

	/**
	 * Generates a list of userinformation for a user. The information includes the name, role, isAdmin and extra
	 * credentials. See {@link org.ogema.frameworkadministration.json.get.UserInformationJsonGet} for message format.
	 * 
	 * @param name
	 *            the name of the user as string
	 * @return a list of userinformation for a given user in json.
	 */
	public String getUserInformation(String name) {

		String result = "{}";

		User user = (User) accessManager.getRole(name);

		// TODO: check object type
		@SuppressWarnings("unchecked")
		Dictionary<Object, Object> credentials = user.getCredentials();
		@SuppressWarnings("unchecked")
		Dictionary<Object, Object> properties = user.getProperties();

		Map<Object, Object> map = new HashMap<Object, Object>();

		Enumeration<Object> enumsDict = credentials.keys();
		while (enumsDict.hasMoreElements()) {
			Object key = enumsDict.nextElement();
			Object value = credentials.get(key);
			map.put(key, value);
		}

		Enumeration<Object> enumsProp = properties.keys();
		while (enumsProp.hasMoreElements()) {
			Object key = enumsProp.nextElement();
			Object value = properties.get(key);
			map.put(key, value);
		}

		map.remove("password");

		UserInformationJsonGet userInformation = new UserInformationJsonGet();
		userInformation.setName(name);
		userInformation.setIsAdmin(checkUserAdmin(name));
		userInformation.setCredentials(map);

		ObjectMapper mapper = new ObjectMapper();

		try {
			result = mapper.writeValueAsString(userInformation);
		} catch (IOException ex) {
			Logger.getLogger(FrameworkAdministration.class.getName()).log(Level.SEVERE, null, ex);
		}

		return result;
	}

	public AccessManager getAccessManager() {
		return accessManager;
	}

	public void setAccessManager(AccessManager accessManager) {
		this.accessManager = accessManager;
	}

}
