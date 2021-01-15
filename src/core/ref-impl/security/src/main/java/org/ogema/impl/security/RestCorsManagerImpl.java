package org.ogema.impl.security;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;
import org.ogema.accesscontrol.RestCorsManager;
import org.osgi.framework.BundleContext;
import org.slf4j.LoggerFactory;

@Component
@Service(RestCorsManager.class)
public class RestCorsManagerImpl implements RestCorsManager {
	
	private static final String ALLOWED_ORIGIN_PROPERTY = "org.ogema.rest.allowedOrigin";
	private static final String MAX_AGE_PROPERTY = "org.ogema.rest.allowedOriginMaxAge";
	private static final int DEFAULT_MAX_AGE = 600; // 10 min

	private List<String> allowedOrigins;
	/**
	 * In seconds. A values of -1 disables caching, a value < -1 indicates not to set the header at all 
	 * (which may default to a short caching interval, such as 5s, depending on the browser). Typical value
	 * ranges between a few seconds and a few hours.
	 * Default value: 10min
	 * 
	 * The allowed value range is capped, depending on the browser, see  
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
	 */
	private int maxAge;
	
	@Activate
	protected void activate(final BundleContext ctx) {
		final String allowedOrigin0 = AccessController.doPrivileged(new PrivilegedAction<String>() {

			@Override
			public String run() {
				return ctx.getProperty(ALLOWED_ORIGIN_PROPERTY);
			}
		});
		if (allowedOrigin0 == null || allowedOrigin0.trim().isEmpty()) {
			this.allowedOrigins = null;
			return;
		}
		final String allowedOriginMaxAge = AccessController.doPrivileged(new PrivilegedAction<String>() {

			@Override
			public String run() {
				return ctx.getProperty(MAX_AGE_PROPERTY);
			}
		});
		final List<String> origins= new ArrayList<>();
		for (String o: allowedOrigin0.split(",")) {
			final String o2 = o.trim();
			if (!o2.isEmpty())
				origins.add(o2);
		}
		this.allowedOrigins = origins;
		if (allowedOriginMaxAge != null) {
			try {
				this.maxAge = Integer.parseInt(allowedOriginMaxAge);
			} catch (NumberFormatException e) {
				LoggerFactory.getLogger(RestCorsManagerImpl.class).warn("Invalid max age property {}: {}. Should be an integer. Disabling CORS maxAge property.",
						MAX_AGE_PROPERTY, allowedOriginMaxAge);
				this.maxAge = -2;
			}
		} else {
			this.maxAge = DEFAULT_MAX_AGE;
		}
	}

	@Override
	public void handleOptionsRequest(final HttpServletRequest req, final HttpServletResponse resp, final String allowedMethods, final boolean doSubmit) {
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
        			if (this.maxAge > -2)
        				resp.setHeader("Access-Control-Max-Age", String.valueOf(this.maxAge));
        		}
        	}
        }
        if (doSubmit)
        	resp.setStatus(200);
	}
	
	@Override
	public void handleOtherRequest(final HttpServletRequest req, final HttpServletResponse resp) {
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
