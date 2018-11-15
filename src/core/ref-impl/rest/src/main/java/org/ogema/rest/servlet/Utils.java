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

import javax.servlet.http.HttpServletRequest;

public class Utils {
	
	public static final String JSON = "application/json";
	public static final String XML = "application/xml";

	public static boolean xmlOrJson(final HttpServletRequest req) {
		String accept = req.getHeader("Accept");
		if (accept == null || accept.equals("*/*")) {
			String contentType = req.getHeader("Content-Type");
			if (contentType != null) {
				contentType = contentType.toLowerCase();
				if (contentType.startsWith(XML))
					return true;
				if (contentType.startsWith(JSON))
					return false;
			}
			return true; // undetermined; xml as default
		}
		accept = accept.toLowerCase();
		if (accept.contains(JSON))
			return false;
//		if (accept.contains(XML))
//			return true;
		return true; // default: xml
	}
	
}
