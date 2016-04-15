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
import org.neociclo.odetteftp.oftplet.AnswerReasonInfo;
import org.neociclo.odetteftp.protocol.AnswerReason;
import org.neociclo.odetteftp.protocol.DefaultVirtualFile;
import org.neociclo.odetteftp.protocol.DeliveryNotification;
import org.neociclo.odetteftp.protocol.OdetteFtpObject;
import org.neociclo.odetteftp.protocol.VirtualFile;
import org.neociclo.odetteftp.security.MappedCallbackHandler;
import org.neociclo.odetteftp.security.PasswordCallback;
import org.neociclo.odetteftp.service.TcpClient;
import org.neociclo.odetteftp.support.InOutSharedQueueOftpletFactory;
import org.neociclo.odetteftp.support.OdetteFtpConfiguration;
import org.neociclo.odetteftp.support.OftpletEventListenerAdapter;
import org.neociclo.odetteftp.support.PasswordHandler;
import org.neociclo.odetteftp.util.IoUtil;

import java.io.File;
import java.io.IOException;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.neociclo.odetteftp.TransferMode.SENDER_ONLY;

/**
 * @author Rafael Marins
 */
public class HandlingSendFileEvents {

	public static void main(String[] args) throws Exception {

		MainSupport ms = new MainSupport(HandlingSendFileEvents.class, args, "server", "port", "odetteid", "password",
				"payload");
		args = ms.args();

		String server = args[0];
		int port = Integer.parseInt(args[1]);
		String userCode = args[2];
		String userPassword = args[3];
		final File payload = new File(args[4]);

		OdetteFtpConfiguration conf = new OdetteFtpConfiguration();
		conf.setTransferMode(SENDER_ONLY);

		MappedCallbackHandler securityCallbacks = new MappedCallbackHandler();
		securityCallbacks.addHandler(PasswordCallback.class,
				new PasswordHandler(userCode, userPassword));

		final Queue<OdetteFtpObject> filesToSend = new ConcurrentLinkedQueue<OdetteFtpObject>();

		DefaultVirtualFile vf = new DefaultVirtualFile();
		vf.setFile(payload);

		filesToSend.offer(vf);

		InOutSharedQueueOftpletFactory factory = new InOutSharedQueueOftpletFactory(
				conf, securityCallbacks, filesToSend, null, null);
		TcpClient oftp = new TcpClient();
		oftp.setOftpletFactory(factory);

		factory.setEventListener(new OftpletEventListenerAdapter() {

			// handle sent file end-to-end response
			@Override
			public void onNotificationReceived(DeliveryNotification notif) {
				System.out.println("Received EERP: " + notif);
			}

			@Override
			public void onSendFileStart(VirtualFile virtualFile,
					long answerCount) {

				File sourceFile = virtualFile.getFile();
				File tempFile = null;

				try {
					tempFile = File.createTempFile("oftp-", ".sent");
					IoUtil.copy(sourceFile, tempFile);

					System.out
							.println("Copying payload in temporary before sending: "
									+ tempFile);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

			@Override
			public void onSendFileEnd(VirtualFile virtualFile) {
				File tempFile = virtualFile.getFile();
				IoUtil.delete(tempFile);
				System.out.println("Deleting temporary payload file: "
						+ tempFile);
			}

			// send file errors
			@Override
			public void onSendFileError(VirtualFile virtualFile,
					AnswerReasonInfo reason, boolean retryLater) {

				// re-send file with different name
				if (reason.getAnswerReason() == AnswerReason.DUPLICATE_FILE) {
					DefaultVirtualFile renamedFile = new DefaultVirtualFile();
					renamedFile.setFile(payload);
					renamedFile.setDatasetName(payload.getName() + "-"
							+ (new Random()).nextInt(100));
					filesToSend.add(renamedFile);
				} else {
					System.out.println("Send File Error: " + reason);
				}
			}

		});

		// perform connection and transfer
		oftp.connect(server, port, true);

	}

}
