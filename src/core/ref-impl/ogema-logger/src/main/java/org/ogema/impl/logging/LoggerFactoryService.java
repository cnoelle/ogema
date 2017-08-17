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
package org.ogema.impl.logging;

import java.util.List;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.ogema.core.administration.AdminLogger;
import org.ogema.core.logging.LoggerFactory;
import org.ogema.core.logging.OgemaLogger;

/**
 * Provides access to the DefaultLoggerFactory singleton as an OSGi service.
 * 
 * @author jlapp
 */
@Component(immediate = true)
@Service(LoggerFactory.class)
public class LoggerFactoryService implements LoggerFactory {

	@Override
	public OgemaLogger getLogger(Class<?> clazz) {
		return DefaultLoggerFactory.INSTANCE.getLogger(clazz);
	}

	@Override
	public OgemaLogger getLogger(String name) {
		return DefaultLoggerFactory.INSTANCE.getLogger(name);
	}

	public List<AdminLogger> getAllLoggers() {
		return DefaultLoggerFactory.INSTANCE.getAdminLoggers();
	}
	
	// https://logback.qos.ch/manual/appenders.html
	// Even if a SocketAppender is no longer attached to any logger, it will not be garbage collected 
	// in the presence of a connector thread. A connector thread exists only if the connection to the server is down. 
	// To avoid this garbage collection problem, you should close the SocketAppender explicitly. Long lived applications 
	// which create/destroy many SocketAppender instances should be aware of this garbage collection problem. 
	// Most other applications can safely ignore it. 
	// TODO 
//	@Deactivate
//	protected void deactivate() {
//	}
//	@Activate
//	protected void activate() {
//	}

}
