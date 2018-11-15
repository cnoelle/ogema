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
package org.ogema.tools.grafana.base;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;
import org.ogema.core.application.Application;
import org.ogema.core.application.ApplicationManager;

@Component(specVersion = "1.2")
@Service(Application.class)
public class GrafanaBaseApp implements Application {

	public static String WEB_RES_PATH;
	private ApplicationManager am;
	public static long APP_STARTTIME;

	// required at all?
	@Override
	public void start(ApplicationManager am) {
		this.am = am;
		String packagePath = "org/ogema/tools/grafana/base/grafana-1.9.1";
		WEB_RES_PATH = am.getWebAccessManager().registerWebResourcePath("", packagePath);
		APP_STARTTIME = am.getFrameworkTime();
		//    	WEB_RES_PATH = am.getWebAccessManager().registerWebResource("/org/ogema/tools/grafana-base" , packagePath);      
		am.getLogger().debug("Grafana base resources registered under " + WEB_RES_PATH);
		am.getWebAccessManager().registerStartUrl(null); // remove app from framework GUI
	}

	@Override
	public void stop(AppStopReason asr) {
		if (am != null)
			am.getWebAccessManager().unregisterWebResourcePath("");
		am = null;
	}

}
