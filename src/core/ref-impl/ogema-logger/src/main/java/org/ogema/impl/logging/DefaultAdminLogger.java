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
package org.ogema.impl.logging;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;

import org.ogema.core.administration.AdminLogger;
import org.ogema.core.logging.LogLevel;
import org.ogema.core.logging.LogOutput;

import org.slf4j.Marker;

/**
 * wrapper for DefaultLogger that adds the AdminLogger methods
 * 
 * @author jlapp
 */
public class DefaultAdminLogger implements AdminLogger {

	public static final long UNKNOWNSIZE = -1;

	protected DefaultLogger logger;

	protected DefaultAdminLogger(DefaultLogger logger) {
		this.logger = logger;
	}
    
    static void storeOverrides(String name, LogOutput output, LogLevel level) {
        String currentSetting = DefaultLogger.loglevel_overrides.getProperty(name);
        try {
            StringBuilder newSetting = new StringBuilder();
            boolean first = true;
            if (level != null) {
                newSetting.append(output.name()).append(":").append(level.name());
                first = false;
            }
            for (LogOutput o : LogOutput.values()) {
                if (o != output) {
                    LogLevel ol = getOutputLevel(currentSetting, o);
                    if (ol != null) {
                        if (!first) {
                            newSetting.append(",");
                        }
                        newSetting.append(o.name()).append(":").append(ol.name());
                        first = false;
                    }
                }
            }
            String s = newSetting.toString();
            if (s.isEmpty()) {
                DefaultLogger.loglevel_overrides.remove(name);
            } else {
                DefaultLogger.loglevel_overrides.put(name, s);
            }
        } catch (RuntimeException re) {
            System.err.printf("cannot store override for %s: %s=%s (%s)%n",
                    name, output, level, re.getMessage());
            return;
        }
        File overrideFile = new File(DefaultLogger.overrideFileName);
        try {
            File tmp = File.createTempFile("loglevels_override_out", "tmp", overrideFile.getAbsoluteFile().getParentFile());
            tmp.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(tmp);
                    BufferedOutputStream bos = new BufferedOutputStream(fos)) {
                DefaultLogger.loglevel_overrides.store(bos, "");
            }
            Files.move(tmp.toPath(), overrideFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ex) {
            System.err.printf("cannot store override for %s: %s%n", name, ex);
        }
    }
    
    private static LogLevel getOutputLevel(String overrideSetting, LogOutput out) {
        if (overrideSetting == null) {
            return null;
        }
        int i = overrideSetting.indexOf(out.name()+":");
        if (i == -1) {
            return null;
        }
        String level = overrideSetting.substring(i + out.name().length() + 1);
        int end = level.indexOf(",");
        if (end != -1) {
            level = level.substring(0, end);
        }
        return LogLevel.valueOf(level.trim().toUpperCase());
    }

	@Override
	public File getFilePath() {
		return DefaultLoggerFactory.INSTANCE.getFilePath();
	}

	@Override
	public void overwriteMaximumLogLevel(LogOutput output, LogLevel level) {
		if (output == null) {
			throw new IllegalArgumentException("output must not be null");
		}
		logger.overrideLogLevel(output, level);
        storeOverrides(getName(), output, level);
	}

	@Override
	public long getMaximumSize(LogOutput output) {
		switch (output) {
		case CACHE:
			return DefaultLoggerFactory.INSTANCE.getCacheSize();
		case FILE:
			return DefaultLoggerFactory.INSTANCE.getLogfileSize();
		default:
			return UNKNOWNSIZE;
		}
	}

	@Override
	public void setMaximumSize(LogOutput output, long bytes) {
		switch (output) {
		case CACHE: {
			DefaultLoggerFactory.INSTANCE.setCacheSize(bytes);
			break;
		}
		case FILE: {
			DefaultLoggerFactory.INSTANCE.setLogfileSize(bytes);
			break;
		}
		}
	}

	// ------------- only delegate methods below this point ------------------

	@Override
	public LogLevel getMaximumLogLevel(LogOutput output) {
		return logger.getMaximumLogLevel(output);
	}

	@Override
	public void setMaximumLogLevel(LogOutput output, LogLevel level) {
		logger.setMaximumLogLevel(output, level);
	}

	@Override
	public boolean saveCache() {
		return logger.saveCache();
	}

	@Override
	public List<String> getCache() {
		return logger.getCache();
	}

	@Override
	public String getName() {
		return logger.getName();
	}

	@Override
	public void trace(String msg) {
		logger.trace(msg);
	}

	@Override
	public void trace(String format, Object arg) {
		logger.trace(format, arg);
	}

	@Override
	public void trace(String format, Object arg1, Object arg2) {
		logger.trace(format, arg1, arg2);
	}

	@Override
	public void trace(String format, Object... argArray) {
		logger.trace(format, argArray);
	}

	@Override
	public void trace(String msg, Throwable t) {
		logger.trace(msg, t);
	}

	@Override
	public void trace(Marker marker, String msg) {
		logger.trace(marker, msg);
	}

	@Override
	public void trace(Marker marker, String format, Object arg) {
		logger.trace(marker, format, arg);
	}

	@Override
	public void trace(Marker marker, String format, Object arg1, Object arg2) {
		logger.trace(marker, format, arg1, arg2);
	}

	@Override
	public void trace(Marker marker, String format, Object... argArray) {
		logger.trace(marker, format, argArray);
	}

	@Override
	public void trace(Marker marker, String msg, Throwable t) {
		logger.trace(marker, msg, t);
	}

	@Override
	public void debug(String msg) {
		logger.debug(msg);
	}

	@Override
	public void debug(String format, Object arg) {
		logger.debug(format, arg);
	}

	@Override
	public void debug(String format, Object arg1, Object arg2) {
		logger.debug(format, arg1, arg2);
	}

	@Override
	public void debug(String format, Object... argArray) {
		logger.debug(format, argArray);
	}

	@Override
	public void debug(String msg, Throwable t) {
		logger.debug(msg, t);
	}

	@Override
	public void debug(Marker marker, String msg) {
		logger.debug(marker, msg);
	}

	@Override
	public void debug(Marker marker, String format, Object arg) {
		logger.debug(marker, format, arg);
	}

	@Override
	public void debug(Marker marker, String format, Object arg1, Object arg2) {
		logger.debug(marker, format, arg1, arg2);
	}

	@Override
	public void debug(Marker marker, String format, Object... argArray) {
		logger.debug(marker, format, argArray);
	}

	@Override
	public void debug(Marker marker, String msg, Throwable t) {
		logger.debug(marker, msg, t);
	}

	@Override
	public void error(String msg) {
		logger.error(msg);
	}

	@Override
	public void error(String format, Object arg) {
		logger.error(format, arg);
	}

	@Override
	public void error(String format, Object arg1, Object arg2) {
		logger.error(format, arg1, arg2);
	}

	@Override
	public void error(String format, Object... argArray) {
		logger.error(format, argArray);
	}

	@Override
	public void error(String msg, Throwable t) {
		logger.error(msg, t);
	}

	@Override
	public void error(Marker marker, String msg) {
		logger.error(marker, msg);
	}

	@Override
	public void error(Marker marker, String format, Object arg) {
		logger.error(marker, format, arg);
	}

	@Override
	public void error(Marker marker, String format, Object arg1, Object arg2) {
		logger.error(marker, format, arg1, arg2);
	}

	@Override
	public void error(Marker marker, String format, Object... argArray) {
		logger.error(marker, format, argArray);
	}

	@Override
	public void error(Marker marker, String msg, Throwable t) {
		logger.error(marker, msg, t);
	}

	@Override
	public void info(String msg) {
		logger.info(msg);
	}

	@Override
	public void info(String format, Object arg) {
		logger.info(format, arg);
	}

	@Override
	public void info(String format, Object arg1, Object arg2) {
		logger.info(format, arg1, arg2);
	}

	@Override
	public void info(String format, Object... argArray) {
		logger.info(format, argArray);
	}

	@Override
	public void info(String msg, Throwable t) {
		logger.info(msg, t);
	}

	@Override
	public void info(Marker marker, String msg) {
		logger.info(marker, msg);
	}

	@Override
	public void info(Marker marker, String format, Object arg) {
		logger.info(marker, format, arg);
	}

	@Override
	public void info(Marker marker, String format, Object arg1, Object arg2) {
		logger.info(marker, format, arg1, arg2);
	}

	@Override
	public void info(Marker marker, String format, Object... argArray) {
		logger.info(marker, format, argArray);
	}

	@Override
	public void info(Marker marker, String msg, Throwable t) {
		logger.info(marker, msg, t);
	}

	@Override
	public void warn(String msg) {
		logger.warn(msg);
	}

	@Override
	public void warn(String msg, Throwable t) {
		logger.warn(msg, t);
	}

	@Override
	public void warn(String format, Object arg) {
		logger.warn(format, arg);
	}

	@Override
	public void warn(String format, Object arg1, Object arg2) {
		logger.warn(format, arg1, arg2);
	}

	@Override
	public void warn(String format, Object... argArray) {
		logger.warn(format, argArray);
	}

	@Override
	public void warn(Marker marker, String msg) {
		logger.warn(marker, msg);
	}

	@Override
	public void warn(Marker marker, String format, Object arg) {
		logger.warn(marker, format, arg);
	}

	@Override
	public void warn(Marker marker, String format, Object... argArray) {
		logger.warn(marker, format, argArray);
	}

	@Override
	public void warn(Marker marker, String format, Object arg1, Object arg2) {
		logger.warn(marker, format, arg1, arg2);
	}

	@Override
	public void warn(Marker marker, String msg, Throwable t) {
		logger.warn(marker, msg, t);
	}

	@Override
	public String toString() {
		return logger.toString();
	}

	@Override
	public boolean isDebugEnabled() {
		return logger.isDebugEnabled();
	}

	@Override
	public boolean isDebugEnabled(Marker marker) {
		return logger.isDebugEnabled(marker);
	}

	@Override
	public boolean isInfoEnabled() {
		return logger.isInfoEnabled();
	}

	@Override
	public boolean isInfoEnabled(Marker marker) {
		return logger.isInfoEnabled(marker);
	}

	@Override
	public boolean isTraceEnabled() {
		return logger.isTraceEnabled();
	}

	@Override
	public boolean isTraceEnabled(Marker marker) {
		return logger.isTraceEnabled(marker);
	}

	@Override
	public boolean isErrorEnabled() {
		return logger.isErrorEnabled();
	}

	@Override
	public boolean isErrorEnabled(Marker marker) {
		return logger.isErrorEnabled(marker);
	}

	@Override
	public boolean isWarnEnabled() {
		return logger.isWarnEnabled();
	}

	@Override
	public boolean isWarnEnabled(Marker marker) {
		return logger.isWarnEnabled(marker);
	}

}
