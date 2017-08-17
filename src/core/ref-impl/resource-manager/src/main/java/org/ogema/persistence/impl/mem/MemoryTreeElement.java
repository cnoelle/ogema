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
package org.ogema.persistence.impl.mem;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.ogema.core.model.Resource;
import org.ogema.core.model.ResourceList;
import org.ogema.resourcetree.SimpleResourceData;
import org.ogema.resourcetree.TreeElement;

/**
 *
 * @author jlapp
 */
public class MemoryTreeElement implements TreeElement {

    protected static final AtomicInteger RESOURCE_IDS = new AtomicInteger(0);
    
    private final boolean decorating;
    private final boolean array;
    private Class<? extends Resource> type;
    private volatile TreeElement parent;
    private final String name;
    private final int resId;
    private final Map<String, MemoryTreeElement> children = new HashMap<>();

    private volatile String appID;
    private volatile Object resRef;
    private volatile boolean active = false;
    private volatile Class<? extends Resource> listType;
    private volatile SimpleResourceData data;
    
    public MemoryTreeElement(MemoryTreeElement original, TreeElement newParent) {
        this(original.name, original.type, newParent, original.decorating);
        this.data = original.data;
        this.active = original.active;
        this.appID = original.appID;
        this.resRef = original.resRef;
        this.listType = original.listType;
        this.children.putAll(original.children);
    }
    
    public MemoryTreeElement(String name, Class<? extends Resource> type, TreeElement parent) {
        this(name, type, parent, false);
    }
    
    public MemoryTreeElement(String name, Class<? extends Resource> type, TreeElement parent, boolean decorating, SimpleResourceData data) {
        this(name,type,parent,decorating);
        this.data = data;
    }

    public MemoryTreeElement(String name, Class<? extends Resource> type, TreeElement parent, boolean decorating) {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(name, "name must not be null");
        this.parent = parent;
        this.resId = RESOURCE_IDS.incrementAndGet();
        this.name = name;
        this.decorating = decorating;

        if (ResourceList.class.isAssignableFrom(type)){
            listType = findElementTypeOnParent();
            array = true;
        } else {
            array = false;
        }
        this.type = type;
    }
    
    @SuppressWarnings("unchecked")
	protected final Class<? extends Resource> findElementTypeOnParent() {
        if (parent == null) {
            return null;
        }
		Class<? extends Resource> pType = parent.getType();
		for (Method m : pType.getMethods()) {
			if (m.getName().equals(getName()) && !m.isBridge() &&!m.isSynthetic() && Resource.class.isAssignableFrom(m.getReturnType())) {
				Type returnType = m.getGenericReturnType();
				if (returnType instanceof ParameterizedType) {
					Type[] actualTypes = ((ParameterizedType) returnType).getActualTypeArguments();
					if (actualTypes.length > 0) {
						return (Class<? extends Resource>) actualTypes[0];
					}
				}
			}
		}
		return null;
	}
    
    @Override
    public String toString() {
        return String.format("%s:%s (%d)", getName(), getType(), getResID());
    }

    @Override
    public String getAppID() {
        return appID;
    }

    @Override
    public void setAppID(String appID) {
        Objects.requireNonNull(appID);
        this.appID = appID;
    }

    @Override
    public Object getResRef() {
        return resRef;
    }

    @Override
    public void setResRef(Object resRef) {
        Objects.requireNonNull(resRef);
        this.resRef = resRef;
    }

    @Override
    public boolean isActive() {
        return active;
    }

    @Override
    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public TreeElement getParent() {
        return parent;
    }

    public void setParent(TreeElement parent) {
    	this.parent = parent;
    }
    
    @Override
    public int getResID() {
        return resId;
    }

    @Override
    public int getTypeKey() {
        throw new UnsupportedOperationException(getClass().getSimpleName()+"#getTypeKey");
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Class<? extends Resource> getType() {
        return type;
    }

    @Override
    public boolean isNonpersistent() {
        throw new UnsupportedOperationException(getClass().getSimpleName()+"#isNonpersistent");
    }

    @Override
    public boolean isDecorator() {
        return decorating;
    }

    @Override
    public boolean isToplevel() {
        return parent == null;
    }

    @Override
    public boolean isReference() {
        return false;
    }

    @Override
    public boolean isComplexArray() {
        return array;
    }

    @Override
    public synchronized TreeElement addChild(String name, Class<? extends Resource> type, boolean isDecorating) {
        if (!isDecorating) {
            Class<?> optionalType = getOptionalElementType(name);
            if (optionalType == null) {
                throw new IllegalArgumentException("not an optional element");
            }
            if (!optionalType.isAssignableFrom(type)) {
                throw new IllegalArgumentException("type does not match definition of optional subresource");
            }
            MemoryTreeElement el = new MemoryTreeElement(name, type, this);
//            el.optional = true;
            children.put(name, el);
            return el;
        } else {
            MemoryTreeElement decorator = new MemoryTreeElement(name, type, this, true);
            children.put(name, decorator);
            return decorator;
        }
    }

    /* return the type of an optional element or null if there is no such element */
    protected Class<?> getOptionalElementType(String optionalName) {
        try {
            Method m = type.getMethod(optionalName);
            return m.getReturnType();
        } catch (NoSuchMethodException ex) {
            return null;
        }
    }

    @Override
    public synchronized TreeElement addReference(TreeElement ref, String name, boolean isDecorating) {
        MemoryTreeElement existingChild = children.get(name);
        if (existingChild != null && existingChild.isReference()){
            ((ReferenceElement)existingChild).setReference(ref);
            return existingChild;
        } else {
            ReferenceElement refElement = new ReferenceElement(ref, name, parent, isDecorating);
            children.put(name, refElement);
            return refElement;
        }
    }

    @Override
    public synchronized SimpleResourceData getData() {
        if (data == null) {
            data = new DefaultSimpleResourceData();
        }
        return data;
    }

    @Override
    public synchronized List<TreeElement> getChildren() {
        List<TreeElement> rval = new ArrayList<>(children.size());
        rval.addAll(children.values());
        return rval;
    }

    @Override
    public synchronized TreeElement getChild(String childName) {
        return children.get(childName);
    }

    @Override
    public TreeElement getReference() {
        throw new UnsupportedOperationException(getClass().getSimpleName()+"#getReference");
    }

    @Override
    public void fireChangeEvent() {
    }

	@Override
	public String getPath() {
		StringBuilder sb = new StringBuilder(getName());
        for (TreeElement e = getParent(); e != null; e = e.getParent()){
            sb.insert(0, "/").insert(0, e.getName());
        }
        return sb.toString();
	}

	@Override
	public Class<? extends Resource> getResourceListType() {
		return listType;
	}

	@Override
	public void setResourceListType(Class<? extends Resource> cls) {
		listType = cls;		
	}

	@Override
	public void setLastModified(long time) {
	}

	@Override
	public long getLastModified() {
		return -1;
	}

	@Override
	public String getLocation() {
		// TODO Auto-generated method stub
		return null;
	}
    
    //XXX MemoryTreeElement should be a VirtualTreeElement (use constrainType)
    public void setType(Class<? extends Resource> type) {
        this.type = type;
    }

}
