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
package org.ogema.drivers.homematic.xmlrpc.hl.events;

import java.util.Locale;
import org.osgi.service.event.Event;

/**
 * Provides a localized message based on an {@link Event}. Intended to be used
 * as an event property, so that the event receivers can choose the locale while
 * the sender provides the localization.
 * 
 * @author jlapp
 */
public interface LocalizableEventMessage {
    
    String getMessage(Locale locale, Event event);
    
}
