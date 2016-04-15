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
package org.neociclo.odetteftp.examples.client;

import org.neociclo.odetteftp.examples.MainSupport;
import org.neociclo.odetteftp.examples.support.SampleOftpSslContextFactory;
import org.neociclo.odetteftp.oftplet.OftpletFactory;
import org.neociclo.odetteftp.protocol.DefaultVirtualFile;
import org.neociclo.odetteftp.protocol.OdetteFtpObject;
import org.neociclo.odetteftp.security.MappedCallbackHandler;
import org.neociclo.odetteftp.security.PasswordCallback;
import org.neociclo.odetteftp.service.TcpClient;
import org.neociclo.odetteftp.support.InOutSharedQueueOftpletFactory;
import org.neociclo.odetteftp.support.OdetteFtpConfiguration;
import org.neociclo.odetteftp.support.PasswordHandler;

import java.io.File;
import java.net.InetSocketAddress;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.net.ssl.SSLContext;

import static org.neociclo.odetteftp.TransferMode.SENDER_ONLY;

/**
 * @author Rafael Marins
 */
public class SecureConnectionSendFile {

	public static void main(String[] args) throws Exception {

		MainSupport ms = new MainSupport(SecureConnectionSendFile.class, args, "server", "port", "odetteid", "password",
				"payload");
		args = ms.args();

		String host = args[0];
		int port = Integer.parseInt(args[1]);
		String userCode = args[2];
		String userPassword = args[3];
		File payload = new File(args[4]);

		OdetteFtpConfiguration conf = new OdetteFtpConfiguration();
		conf.setTransferMode(SENDER_ONLY);

		MappedCallbackHandler securityCallbacks = new MappedCallbackHandler();
		securityCallbacks.addHandler(PasswordCallback.class,
				new PasswordHandler(userCode, userPassword));

		Queue<OdetteFtpObject> filesToSend = new ConcurrentLinkedQueue<OdetteFtpObject>();

		DefaultVirtualFile vf = new DefaultVirtualFile();
		vf.setDatasetName(payload.getName());
		vf.setFile(payload);

		filesToSend.offer(vf);

		// create the client mode SSL context
		SSLContext sslContext = SampleOftpSslContextFactory.getClientContext();

		OftpletFactory factory = new InOutSharedQueueOftpletFactory(conf, securityCallbacks, filesToSend, null, null);
		TcpClient oftp = new TcpClient(sslContext);
		oftp.setOftpletFactory(factory);

		oftp.connect(new InetSocketAddress(host, port), true);

	}

}
