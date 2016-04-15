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
package org.neociclo.odetteftp.examples.server;

import org.neociclo.odetteftp.oftplet.Oftplet;
import org.neociclo.odetteftp.oftplet.OftpletFactory;
import org.neociclo.odetteftp.security.MappedCallbackHandler;
import org.neociclo.odetteftp.support.OdetteFtpConfiguration;
import org.neociclo.odetteftp.support.OftpletEventListener;

import java.io.File;

/**
 * @author Rafael Marins
 */
public class SimpleServerOftpletFactory implements OftpletFactory {

	private File serverBaseDir;
	private OdetteFtpConfiguration config;
	private OftpletEventListener listener;
	private MappedCallbackHandler securityCallbackHandler;

	public SimpleServerOftpletFactory(File serverBaseDir, OdetteFtpConfiguration config, MappedCallbackHandler serverSecurityHandler) {
		this(serverBaseDir, config, serverSecurityHandler, null);
	}

	public SimpleServerOftpletFactory(File serverBaseDir, OdetteFtpConfiguration config, MappedCallbackHandler serverSecurityHandler, OftpletEventListener listener) {
		super();
		this.serverBaseDir = serverBaseDir;
		this.config = config;
		this.securityCallbackHandler = serverSecurityHandler;
		this.listener = listener;
	}

	public Oftplet createProvider() {
		return new SimpleServerOftplet(serverBaseDir, config, securityCallbackHandler, listener);
	}

}
