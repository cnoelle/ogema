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
package org.ogema.webresourcemanager.impl.internal.contact;

import org.ogema.apps.wicket.ApplicationPanel;

public class ContactPanel extends ApplicationPanel {

    private static final long serialVersionUID = 3574779385959388617L;
    private static ContactPanel contact = null;

    public static ContactPanel getInstance() {
        if (ContactPanel.contact == null) {
            ContactPanel.contact = new ContactPanel();
        }
        return ContactPanel.contact;
    }

    @Override
    public String getTitle() {
        return "Contact";
    }

    @Override
    public void initContent() {

    }

}
