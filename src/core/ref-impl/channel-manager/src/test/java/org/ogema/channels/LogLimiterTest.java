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
package org.ogema.channels;

import static org.junit.Assert.*;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.Marker;

public class LogLimiterTest {

	private LoggerImpl logger = new LoggerImpl();
	
	private LogLimiter logLimiter = new LogLimiter(logger);
	
	@Test
	public void testLogLimiting() throws Exception {
		
		long count = 0;
		
		for (long i = 0; i < 100; i++) {
			if (logLimiter.check())
				count++;
		}
		
		assertEquals(0, logger.warnCount);
		assertEquals(1, count);
		
		Thread.sleep(600);

		assertEquals(1, logger.warnCount);
		assertEquals(1, count);

		for (long i = 0; i < 100; i++) {
			if (logLimiter.check())
				count++;
		}
		
		assertEquals(1, logger.warnCount);
		assertEquals(2, count);
		
		Thread.sleep(600);

		assertEquals(2, logger.warnCount);
		assertEquals(2, count);
	}
	
	private class LoggerImpl implements Logger {

		long warnCount;
		
		@Override
		public String getName() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean isTraceEnabled() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void trace(String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isTraceEnabled(Marker marker) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void trace(Marker marker, String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(Marker marker, String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(Marker marker, String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(Marker marker, String format, Object... argArray) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void trace(Marker marker, String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isDebugEnabled() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void debug(String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isDebugEnabled(Marker marker) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void debug(Marker marker, String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(Marker marker, String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(Marker marker, String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(Marker marker, String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void debug(Marker marker, String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isInfoEnabled() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void info(String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isInfoEnabled(Marker marker) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void info(Marker marker, String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(Marker marker, String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(Marker marker, String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(Marker marker, String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void info(Marker marker, String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isWarnEnabled() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void warn(String msg) {
			warnCount++;
			
		}

		@Override
		public void warn(String format, Object arg) {
			warnCount++;
			
		}

		@Override
		public void warn(String format, Object... arguments) {
			warnCount++;
			
		}

		@Override
		public void warn(String format, Object arg1, Object arg2) {
			warnCount++;
			
		}

		@Override
		public void warn(String msg, Throwable t) {
			warnCount++;
		}

		@Override
		public boolean isWarnEnabled(Marker marker) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void warn(Marker marker, String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void warn(Marker marker, String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void warn(Marker marker, String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void warn(Marker marker, String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void warn(Marker marker, String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isErrorEnabled() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void error(String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isErrorEnabled(Marker marker) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void error(Marker marker, String msg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(Marker marker, String format, Object arg) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(Marker marker, String format, Object arg1, Object arg2) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(Marker marker, String format, Object... arguments) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void error(Marker marker, String msg, Throwable t) {
			// TODO Auto-generated method stub
			
		}
		
	}
}
