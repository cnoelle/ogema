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
package org.ogema.rest.servlet;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ogema.accesscontrol.PermissionManager;
import org.ogema.accesscontrol.RestAccess;
import org.ogema.accesscontrol.RestCorsManager;
import org.ogema.core.application.ApplicationManager;
import org.ogema.core.model.Resource;
import org.ogema.rest.servlet.ResourceTypeWriters.ResourceTypeWriter;

//@Component
//@Service(Servlet.class)
//@Property(name = HttpWhiteboardConstants.HTTP_WHITEBOARD_SERVLET_PATTERN, value = RestTypesServlet.ALIAS)
class RestTypesServlet extends HttpServlet  {

	private static final String SUPPORTED_METHODS = "GET, OPTIONS";
	private static final long serialVersionUID = 1L;

	final static String ALIAS = "/rest/resourcelists";

	/**
	 * URL parameter defining the maximum depth of the resource tree in the response, default is 0, i.e. transfer only
	 * the requested resource and include subresources only as references.
	 */
	public static final String PARAM_RECURSIVE = "recursive";
//	private static final boolean DEFAULT_TOPLEVEL_ONLY = false;
	
	public static final String PARAM_TYPE = "type";

	private final PermissionManager permMan;
	private final RestAccess restAcc;
	private final RestCorsManager cors;
	
	RestTypesServlet(PermissionManager permMan, RestAccess restAcc, RestCorsManager cors) {
		this.permMan = Objects.requireNonNull(permMan);
		this.restAcc = Objects.requireNonNull(restAcc);
		this.cors = Objects.requireNonNull(cors);
	}

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	this.cors.handleOptionsRequest(req, resp, SUPPORTED_METHODS, true);
    }

	// TODO get subresources of specific type
	@SuppressWarnings("unchecked")
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		final ApplicationManager appman = restAcc.authenticate(req, resp);
		if (appman == null) {
			return;
		}
		this.cors.handleOtherRequest(req, resp);
		try {
			resp.setCharacterEncoding("UTF-8");
			ResourceTypeWriter w = ResourceTypeWriters.forRequest(req, appman);
			if (w == null) {
				resp.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE);
				return;
			}
			resp.setContentType(w.contentType());
			String clazzName = req.getParameter(PARAM_TYPE);
	
			Class<? extends Resource> type = null;
			if (clazzName != null) {
				try {
					type = (Class<? extends Resource>) Class.forName(clazzName);  // TODO access available resource types?
				} catch (ClassNotFoundException e) {} 
			}
			if (type == null) {
				resp.sendError(HttpServletResponse.SC_NOT_FOUND);
				return;
			}
			w.write(type, resp.getWriter());
			resp.flushBuffer();
		} catch (SecurityException se) {
			RestApp.logger.debug("Security exception in GET request ", se);
			resp.sendError(HttpServletResponse.SC_FORBIDDEN);
		} catch (Exception e) {
			RestApp.logger.debug("Exception in GET request",e);
			resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		} finally {
			permMan.resetAccessContext();
		}
	}
	
	// TODO POST, PUT, DELETE

}
