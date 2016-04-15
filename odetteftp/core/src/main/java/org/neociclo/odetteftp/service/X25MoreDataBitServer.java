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
package org.neociclo.odetteftp.service;

import org.neociclo.odetteftp.TransportType;
import org.neociclo.odetteftp.oftplet.OftpletFactory;

import java.net.InetSocketAddress;

import javax.net.ssl.SSLContext;

/**
 * @author Rafael Marins
 */
public class X25MoreDataBitServer extends TcpServer {

	private static final TransportType X25_MBGW_TRANSPORT_TYPE = TransportType.X25_MBGW;

	public X25MoreDataBitServer(InetSocketAddress localAddress, OftpletFactory oftpletFactory) {
		super(localAddress, oftpletFactory);
	}

	public X25MoreDataBitServer(InetSocketAddress localAddress, SSLContext sslContext, OftpletFactory oftpletFactory) {
		super(localAddress, sslContext, oftpletFactory);
	}

	public X25MoreDataBitServer(InetSocketAddress localAddress, SSLContext sslContext, Boolean startTls,
			OftpletFactory oftpletFactory) {
		super(localAddress, sslContext, startTls, oftpletFactory);
	}

	@Override
	public TransportType getTransportType() {
		return X25_MBGW_TRANSPORT_TYPE;
	}
}
