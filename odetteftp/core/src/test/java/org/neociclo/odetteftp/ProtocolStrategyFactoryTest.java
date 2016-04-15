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
package org.neociclo.odetteftp;

import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.neociclo.odetteftp.OdetteFtpVersion.OFTP_V12;
import static org.neociclo.odetteftp.OdetteFtpVersion.OFTP_V13;
import static org.neociclo.odetteftp.OdetteFtpVersion.OFTP_V14;
import static org.neociclo.odetteftp.OdetteFtpVersion.OFTP_V20;

/**
 * @author Rafael Marins
 */
public class ProtocolStrategyFactoryTest {

    @Test
    public void testSupportedProtocolVersions() {
        assertTrue(OFTP_V12.toString(), ProtocolHandlerFactory.isProtocolVersionSupported(OFTP_V12));
        assertTrue(OFTP_V13.toString(), ProtocolHandlerFactory.isProtocolVersionSupported(OFTP_V13));
        assertTrue(OFTP_V14.toString(), ProtocolHandlerFactory.isProtocolVersionSupported(OFTP_V14));
        assertTrue(OFTP_V20.toString(), ProtocolHandlerFactory.isProtocolVersionSupported(OFTP_V20));
    }

}
