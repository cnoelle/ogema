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
package org.ogema.resourcemanager.impl.transaction.actions;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Objects;
import java.util.Queue;

import org.ogema.core.model.Resource;
import org.ogema.core.resourcemanager.ResourceOperationException.Type;
import org.ogema.core.resourcemanager.VirtualResourceException;
import org.ogema.resourcemanager.impl.transaction.AtomicAction;

public class ActivationAction implements AtomicAction {
	
	private final Resource target;
	private final boolean activate;
	private final boolean recursive;
	private final boolean create; // ignore for deactivation action
	private boolean oldState = false; // for rollback
	private boolean done;
	private boolean setBack;
	private final Queue<AtomicAction> subactions = new ArrayDeque<>();
	private final Deque<AtomicAction> subactionsDone = new ArrayDeque<>();
	
	public ActivationAction(Resource target, boolean activate, boolean recursive, boolean create) {
		Objects.requireNonNull(target);
		this.target = target;
		this.activate = activate;
		this.recursive = recursive;
		this.create = create;
	}
	
	private void buildActionsTree() {
		if (create && activate) {
			subactions.add(new CreationAction(target));
		}
		if (!recursive)
			return;
		List<Resource> subs = target.getDirectSubResources(true);
		for (Resource sub: subs) {
			subactions.add(new ActivationAction(sub, activate, false, false));
		}
	}
	
	private void executeSubActions() throws Exception {
		AtomicAction action;
		while ((action = subactions.poll()) != null) {
			subactionsDone.add(action); // add this immediately, so we'll try to rollback this action even if it fails
			action.execute();
		}
	}
	
	private void rollbackSubactions() throws IllegalStateException {
		AtomicAction action;
		while ((action = subactionsDone.pollLast()) != null) {
			try {
				action.rollback();
			} catch (Exception e) {
				continue;
			}
		}
	}
	
	@Override
	public void execute() throws Exception {
		if (done || setBack)
			throw new IllegalStateException("Transaction has been executed already");
		done = true;
		buildActionsTree(); // we cannot do this earlier, e.g. in the constructor, since at that time no resource lock is held
		executeSubActions();
		if (!target.exists())
			throw new VirtualResourceException("Target resource " + target + " is virtual");
		oldState = target.isActive();
		if (activate)
			target.activate(false);
		else
			target.deactivate(false);
	}

	@Override
	public void rollback() throws IllegalStateException {
		if (!done)
			throw new IllegalStateException("Transaction has not been executed yet, cannot set back");
		if (setBack)
			throw new IllegalStateException("Transaction has been rolled back already");
		setBack =true;
//		if (!existed) {
//			target.delete();
//			return;
//		}
		try {
			if (oldState && !activate)
				target.activate(false);
			else if (!oldState && activate)
				target.deactivate(false);
		} catch (Exception e) {
			// we better ignore this... e.g. it could fail due to missing permissions, in which case already the original action should have failed
		}
		rollbackSubactions();
	}

	@Override
	public boolean requiresStructureWriteLock() {
		return true;
	}

	@Override
	public boolean requiresCommitWriteLock() {
		return false; // XXX?
	}

	@Override
	public Type getType() {
		return activate ? Type.ACTIVATE : Type.DEACTIVATE;
	}

	@Override
	public Resource getSource() {
		return target;
	}

}
