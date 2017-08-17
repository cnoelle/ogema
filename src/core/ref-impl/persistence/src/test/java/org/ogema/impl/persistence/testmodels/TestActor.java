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
package org.ogema.impl.persistence.testmodels;

import org.ogema.core.model.simple.*;
import org.ogema.model.actors.MultiSwitch;

public interface TestActor extends MultiSwitch {

	BooleanResource bool_res();

	FloatResource float_res();

	IntegerResource int_res();

    @SuppressWarnings("deprecation")
	OpaqueResource opaque_res();

	StringResource string_res();

	TimeResource time_res();
}
