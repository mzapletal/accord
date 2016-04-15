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
package org.neociclo.odetteftp.security;

import org.neociclo.odetteftp.OdetteFtpSession;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

/**
 * Convey the received Authentication Challenge request/response with the
 * {@link CallbackHandler}.
 * 
 * @author Rafael Marins
 */
public class AuthenticationChallengeCallback implements Callback {

    private byte[] encodedChallenge;
    private byte[] challenge;
	private OdetteFtpSession session;
    
    /**
     * Constructor.
     * 
     * @param challenge received encoded challenge
     */
    public AuthenticationChallengeCallback(byte[] challenge, OdetteFtpSession session) {
        super();
        this.encodedChallenge = challenge;
        this.session = session;
    }

    public byte[] getEncodedChallenge() {
        return encodedChallenge;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public void setChallenge(byte[] plainChallenge) {
        this.challenge = plainChallenge;
    }

	public OdetteFtpSession getSession() {
		return session;
	}

}
