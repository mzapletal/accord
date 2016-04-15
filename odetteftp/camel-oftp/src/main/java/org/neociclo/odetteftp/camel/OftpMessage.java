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
package org.neociclo.odetteftp.camel;

import org.apache.camel.impl.DefaultMessage;
import org.apache.camel.util.ExchangeHelper;
import org.neociclo.odetteftp.OdetteFtpSession;
import org.neociclo.odetteftp.protocol.OdetteFtpObject;

import java.util.Map;

/**
 * @author Rafael Marins
 */
public class OftpMessage extends DefaultMessage {

	// Message attributes
	public static final String OFTP_MESSAGE_EVENT_NAME = "OftpEventName";
	public static final String OFTP_MESSAGE_COMMAND_NAME = "OftpCommandName";
	/** Return Address EIP */
	public static final String OFTP_REPLY_TO = "OftpReplyTo";
	// OdetteFtpObject attributes
	public static final String OFTP_ORIGINATOR = "OftpOriginator";
	public static final String OFTP_DESTINATION = "OftpDestination";
	public static final String OFTP_DATASET_NAME = "OftpDatasetName";
	public static final String OFTP_USER_DATA = "OftpUserData";
	public static final String OFTP_TIMESTAMP = "OftpTimestamp";
	public static final String OFTP_TIMESTAMP_TICKER = "OftpTimestampTicker";
	// VirtualFile attributes
	public static final String OFTP_VF_RECORD_FORMAT = "OftpRecordFormat";
	public static final String OFTP_VF_RECORD_SIZE = "OftpRecordSize";
	public static final String OFTP_VF_RESTART_OFFSET = "OftpRestartOffset";
	public static final String OFTP_VF_SIZE = "OftpFileSize";
	// EnvelopedVirtualFile attributes
	public static final String OFTP_VF_CIPHER_SUITE = "OftpCipherSuite";
	public static final String OFTP_VF_COMPRESSION_ALGORITHM = "OftpCompressionAlgorithm";
	public static final String OFTP_VF_ENVELOPING_FORMAT = "OftpEnvelopingFormat";
	public static final String OFTP_VF_DESCRIPTION = "OftpFileDescription";
	public static final String OFTP_VF_ORIGINAL_SIZE = "OftpOriginalFileSize";
	public static final String OFTP_VF_SECURITY_LEVEL = "OftpSecurityLevel";
	public static final String OFTP_VF_SIGNED_NOTIFICATION_REQUEST = "OftpSignedNotificationRequest";
	// DeliveryNotification attributes
	public static final String OFTP_NOTIF_CREATOR = "OftpCreator";
	public static final String OFTP_NOTIF_REASON = "OftpNegativeResponseReason";
	public static final String OFTP_NOTIF_REASON_TEXT = "OftpNegativeResponseReasonText";
	public static final String OFTP_NOTIF_TYPE = "OftpNotificationType";
	// SignedDeliveryNotification attributes
	public static final String OFTP_NOTIF_SIGNATURE = "OftpNotifSignature";
	public static final String OFTP_NOTIF_FILE_HASH = "OftpNotifFileHash";
	// Odette FTP Session attributes
	public static final String OFTP_SESSION_DEB_SIZE = "OftpSessionDataExchangeBufferSize";
	public static final String OFTP_SESSION_LOCAL_USER = "OftpSessionLocalUserCode";
	public static final String OFTP_SESSION_REMOTE_USER = "OftpSessionRemoteUserCode";
	public static final String OFTP_SESSION_USER_DATA = "OftpSessionUserData";
	public static final String OFTP_SESSION_SPECIAL_LOGIC = "OftpSessionSpecialLogic";
	public static final String OFTP_SESSION_WINDOW_SIZE = "OftpSessionWindowSize";
	public static final String OFTP_SESSION_VERSION = "OftpSessionVersion";
	public static final String OFTP_SESSION_COMPRESSION = "OftpSessionCompression";
	public static final String OFTP_SESSION_RESTART = "OftpSessionRestart";
	public static final String OFTP_SESSION_SECURE_AUTHENTICATION = "OftpSessionSecureAuth";
	public static final String OFTP_SESSION_CIPHER_SUITE_SELECTION = "OftpSessionCipherSuiteSel";

	public static final String OFTP_FILE_OVERWRITE = "OftpFileOverwrite";
	public static final String OFTP_FORCE_BEGIN_TRANSFER = "OftpForceBeginTransfer";

	private OdetteFtpSession session;
	private OdetteFtpObject oftpObject;

	public OftpMessage() {
		this(null);
	}

	public OftpMessage(OdetteFtpObject obj) {
		this(obj, null);
	}

	public OftpMessage(OdetteFtpObject obj, OdetteFtpSession session) {
		super();
		this.oftpObject = obj;
		this.session = session;
	}

	@Override
	public OftpMessage newInstance() {
		return new OftpMessage();
	}

	public OdetteFtpObject getOftpObject() {
		return oftpObject;
	}

	public void setOftpObject(OdetteFtpObject obj) {
		this.oftpObject = obj;
	}

	@Override
	public String toString() {
		return "OftpMessage [obj: " + (oftpObject == null ? "null" : oftpObject.toString()) + "]";
	}

	// Overriding the MessageSupport implementation
	// -------------------------------------------------------------------------

	@Override
	protected Object createBody() {
		if (oftpObject != null) {
			OftpBinding binding = ExchangeHelper.getBinding(getExchange(), OftpBinding.class);
			return (binding != null ? binding.extractBodyFromOdetteFtpObject(getExchange(), this) : null);
		}
		return null;
	}

	@Override
	protected void populateInitialHeaders(Map<String, Object> map) {
		OftpBinding binding = ExchangeHelper.getBinding(getExchange(), OftpBinding.class);
		if (binding == null) {
			return;
		}

		if (oftpObject != null) {
			map.putAll(binding.extractHeadersFromOdetteFtpObject(oftpObject, getExchange()));
		}

		if (session != null) {
			map.putAll(binding.extractHeadersFromOdetteFtpSession(session, getExchange()));
		}

		Object body = getBody();
		if (body instanceof OftpCommand) {
			map.putAll(binding.extractHeadersFromOftpCommand(this));
		} else if (body instanceof OftpEvent) {
			map.putAll(binding.extractHeadersFromOftpEvent(this));
		}
	}

}
