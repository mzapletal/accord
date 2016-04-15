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
package org.neociclo.odetteftp.netty;

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineException;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.handler.ssl.SslHandler;
import org.jboss.netty.util.Timer;
import org.neociclo.odetteftp.EntityType;
import org.neociclo.odetteftp.TransportType;
import org.neociclo.odetteftp.netty.codec.MoreDataBitDecoder;
import org.neociclo.odetteftp.netty.codec.MoreDataBitEncoder;
import org.neociclo.odetteftp.netty.codec.OdetteFtpDecoder;
import org.neociclo.odetteftp.netty.codec.OdetteFtpEncoder;
import org.neociclo.odetteftp.netty.codec.ProtocolLoggingHandler;
import org.neociclo.odetteftp.netty.codec.StbDecoder;
import org.neociclo.odetteftp.netty.codec.StbEncoder;
import org.neociclo.odetteftp.oftplet.OftpletFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.jboss.netty.channel.Channels.pipeline;
import static org.neociclo.odetteftp.TransportType.TCPIP;
import static org.neociclo.odetteftp.TransportType.X25_MBGW;

/**
 * The default OFTP channel pipeline factory: works for TCPIP and X25
 * MoreDataBit Gateway protocol.
 * 
 * @author Rafael Marins
 */
public class OdetteFtpPipelineFactory implements ChannelPipelineFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(OdetteFtpPipelineFactory.class);

    private EntityType entityType;
    private OftpletFactory oftpletFactory;
    private Timer timer;
    private TransportType transport;
    private SslHandlerFactory sslHandlerFactory;
    private ChannelGroup channelGroup;

	private boolean loggingEnabled = true;

    public OdetteFtpPipelineFactory(EntityType entityType, OftpletFactory oftpletFactory, Timer timer) {
        this(entityType, oftpletFactory, timer, TransportType.TCPIP);
    }

    public OdetteFtpPipelineFactory(EntityType entityType, OftpletFactory oftpletFactory, Timer timer, TransportType transport) {
        this(entityType, oftpletFactory, timer, transport, null);
    }

    public OdetteFtpPipelineFactory(EntityType entityType, OftpletFactory oftpletFactory, Timer timer, TransportType transport, SslHandlerFactory sslHandlerFactory) {
        this(entityType, oftpletFactory, timer, transport, null, null);
    }

    public OdetteFtpPipelineFactory(EntityType entityType, OftpletFactory oftpletFactory, Timer timer, TransportType transport, SslHandlerFactory sslHandlerFactory, ChannelGroup channelGroup) {
        super();

        if (entityType == null) {
            throw new NullPointerException("entityType");
        } else if (oftpletFactory == null) {
            throw new NullPointerException("oftpletFactory");
        } else if (transport == null) {
            throw new NullPointerException("transport");
        } else if (timer == null) {
            throw new NullPointerException("timer");
        }

        this.entityType = entityType;
        this.oftpletFactory = oftpletFactory;
        this.timer = timer;
        this.transport = transport;
        this.sslHandlerFactory = sslHandlerFactory;
        this.channelGroup = channelGroup;

    }

    public ChannelPipeline getPipeline() throws Exception {

        final ChannelPipeline p = pipeline();

        if (sslHandlerFactory != null) {
        	final SslHandler sslHandler = sslHandlerFactory.createSslHandler();
        	if (sslHandler != null) {
		        if (entityType == EntityType.INITIATOR) {
		            p.addLast("sslHandshaker", new SimpleChannelHandler() {
		            	@Override
		            	public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
		                    LOGGER.debug("Starting SSL/TLS client (Initiator) handshake.");
		                    sslHandler.handshake();
		                    p.remove("sslHandshaker");
		                    
		                    super.channelConnected(ctx, e);
		                }
		            });
		        }

		        p.addLast("ssl", sslHandler);
		        LOGGER.debug("Added the SSL Handler to channel pipeline: {}", sslHandler);
        	}
        }

        // add transport type based codecs
        if (transport == TCPIP) {
            // stream transmission buffer
            p.addLast("Stream-Transmission-Buffer-DECODER", new StbDecoder());
            p.addLast("Stream-Transmission-Buffer-ENCODER", new StbEncoder());
            LOGGER.debug("Added Stream Transmission Buffer codecs to channel pipeline.");
        } else if (transport == X25_MBGW) {
            // more data bit gateway
            p.addLast("More-Data-Bit-DECODER", new MoreDataBitDecoder());
            p.addLast("More-Data-Bit-ENCODER", new MoreDataBitEncoder());
            LOGGER.debug("Added MoreDataBit (X25/MBGW) codecs to channel pipeline.");
        } else {
            // unsupported transport
            throw new ChannelPipelineException("Unsupported transport type: " + transport);
        }

        // add odette-ftp exchange buffer codecs
        p.addLast("OdetteExchangeBuffer-DECODER", new OdetteFtpDecoder());
        p.addLast("OdetteExchangeBuffer-ENCODER", new OdetteFtpEncoder());
        LOGGER.debug("Added Odette Exchange Buffer codecs to channel pipeline.");

        if (isLoggingEnabled()) {
	        p.addLast("OdetteFtp-LOGGING", new ProtocolLoggingHandler(null));
	        LOGGER.debug("Added Odette FTP protocol logging handler to channel pipeline.");
        }

        // add odette-ftp handler
        p.addLast("OdetteFtp-HANDLER", new OdetteFtpChannelHandler(entityType, oftpletFactory, timer, channelGroup));
        LOGGER.debug("Added Odette FTP handler to channel pipeline (oftpletFactory={}, timer={}, channelGroup={}).", new Object[] { oftpletFactory,
                timer, channelGroup });

        return p;
    }

	public void disableLogging() {
		this.loggingEnabled = false;
	}

	public void enableLogging() {
		this.loggingEnabled = true;
	}

	public boolean isLoggingEnabled() {
		return loggingEnabled;
	}

}
