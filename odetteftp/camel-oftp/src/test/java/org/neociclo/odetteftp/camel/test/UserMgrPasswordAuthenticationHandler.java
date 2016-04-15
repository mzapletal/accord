/**
 * The Accord Project, http://accordproject.org
 * Copyright (C) 2005-2013 Rafael Marins, http://rafaelmarins.com
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
package org.neociclo.odetteftp.camel.test;

import org.neociclo.odetteftp.protocol.EndSessionReason;
import org.neociclo.odetteftp.support.PasswordAuthenticationHandler;

import java.io.IOException;

/**
 * @author Rafael Marins
 */
public class UserMgrPasswordAuthenticationHandler extends PasswordAuthenticationHandler {

	private IUserManager userManager;
	private EndSessionReason cause;

	public UserMgrPasswordAuthenticationHandler(IUserManager userMgr) {
		super();
		this.userManager = userMgr;
	}

	@Override
	public boolean authenticate(String oid, String pwd) throws IOException {

		AccountInfo account = userManager.getAccount(oid);
		if (account == null) {
			cause = EndSessionReason.UNKNOWN_USER_CODE;
			return false;
		}

		if (pwd.equals(account.getPassword())) {
			return true;
		} else {
			cause = EndSessionReason.INVALID_PASSWORD;
			return false;
		}

	}

	@Override
	public EndSessionReason getCause() {
		return cause;
	}

}
