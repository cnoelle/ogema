package org.ogema.rest.servlet;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CorsTool {

	private final List<String> allowedOrigins;
	
	public CorsTool(List<String> allowedOrigins) {
		this.allowedOrigins = allowedOrigins;
	}

	public void handleOptions(final HttpServletRequest req, final HttpServletResponse resp, final String allowedMethods) {
        resp.setHeader("Allow", allowedMethods);
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        if (this.allowedOrigins != null) {
        	final String origin = req.getHeader("Origin");
        	if (origin != null) {
        		if (this.allowedOrigins.contains("*") || this.allowedOrigins.contains(origin)) {
        			resp.setHeader("Access-Control-Allow-Origin", origin);
        			resp.setHeader("Access-Control-Allow-Credentials", "true");
        			resp.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        			resp.setHeader("Access-Control-Allow-Methods", allowedMethods);
        			resp.setHeader("Vary", "Origin");
        		}
        	}
        }
        resp.setStatus(200);
	}
	
	public void handleOther(final HttpServletRequest req, final HttpServletResponse resp) {
		if (this.allowedOrigins != null) {
        	final String origin = req.getHeader("Origin");
        	if (origin != null) {
        		if (this.allowedOrigins.contains("*") || this.allowedOrigins.contains(origin)) {
        			resp.setHeader("Access-Control-Allow-Origin", origin);
        		}
        	}
        }
	}

}
