package org.ogema.accesscontrol;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Responsible for setting the appropriate CORS headers in the OGEMA REST interface.
 */
public interface RestCorsManager {
	
	/**
	 * Call in a {@link HttpServlet}.doOptions() method in order to set the appropriate response headers.
	 * This is the only action required in a typical doOptions method, 
	 * @param req
	 * @param resp
	 * @param allowedMethods
	 * 		The manager needs to know which HTTP methods (GET, POST, PUT, DELETE, OPTIONS, etc.) are admissible.
	 * 		Pass as comma-separated string, e.g. "OPTIONS, GET, POST"
	 * @param doSubmit
	 * 		if true, the status code 200 will be set and hence the response submitted to the client. Set to false
	 * 		if you still need to manipulate the response after calling this method. 
	 */
	void handleOptionsRequest(HttpServletRequest req, HttpServletResponse resp, String allowedMethods, boolean doSubmit);
	
	/**
	 * Use in a request method other than doOptions, if the Access-Control-Allowed-Origins header shall be set there
	 * @param req
	 * @param resp
	 */
	void handleOtherRequest(HttpServletRequest req, HttpServletResponse resp);

}
