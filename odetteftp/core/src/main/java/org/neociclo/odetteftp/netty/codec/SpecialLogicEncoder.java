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
package org.neociclo.odetteftp.netty.codec;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;

import java.util.concurrent.atomic.AtomicInteger;

import static org.jboss.netty.channel.Channels.future;
import static org.jboss.netty.channel.Channels.write;

/**
 * @author Rafael Marins
 *
 */
public class SpecialLogicEncoder implements ChannelDownstreamHandler {

	public static final int STX = 0x02;
	public static final int CR = 0x0d;
	public static final int SO = 0x0e;

	public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {

        if (!(e instanceof MessageEvent)) {
            ctx.sendDownstream(e);
            return;
        }

        MessageEvent evt = (MessageEvent) e;
        Object msg = evt.getMessage();
        if (!(msg instanceof ChannelBuffer)) {
        	ctx.sendDownstream(evt);
        	return;
        }

        long lastActivityInMillis = System.currentTimeMillis();
        ChannelBuffer oeb = (ChannelBuffer) msg;

//        if (ctx.getAttachment() == null) {
//        	ctx.setAttachment(Byte.valueOf((byte) 1));
//        }

        // prepare the extended exchange buffer & synchronization character
        Channel channel = e.getChannel();
        ChannelBuffer extendedBuffer = channel.getConfig().getBufferFactory().getBuffer(oeb.readableBytes() + 5);
        extendedBuffer.writeByte(STX);

        // get the block sequence number
        int blockSequenceNumber = computeBlockSequenceNumber(ctx);
        extendedBuffer.writeByte(blockSequenceNumber);

        // checksum variables
        int c0 = 0;
        int c1 = 0;

        // do shift-out processing & checksum calculation
        while (oeb.readable()) {

        	// transmit the processed buffer after some delay
        	long currentTimeInMillis = System.currentTimeMillis();
        	if (currentTimeInMillis - lastActivityInMillis >= 1000) {
        		int length = extendedBuffer.readableBytes();
        		ChannelBuffer slice = extendedBuffer.readSlice(length);
        		write(ctx, future(ctx.getChannel()), slice, evt.getRemoteAddress());
        		lastActivityInMillis = System.currentTimeMillis();
        	}

        	// the shift-out processing
        	byte octet = oeb.readByte();
        	if ((octet & 0x7f) < 0x20) {
        		extendedBuffer.writeByte(SO);
        		extendedBuffer.writeByte(octet + 0x20);
        	} else {
        		extendedBuffer.writeByte(octet);
        	}

        	// checksum calculation
        	c0 = (c0 + octet);// % 255;
        	c1 = (c1 + c0);// % 255;

        }

        // checksum finalization
    	int x = c0 - c1;
    	int y = c1 - (2 * c0);

		byte[] blockChecksum = new byte[] { (byte) (x & 0xff), (byte) (y & 0xff) };
        extendedBuffer.writeBytes(blockChecksum);

        // carriage return
        extendedBuffer.writeByte(CR);

        write(ctx, evt.getFuture(), extendedBuffer, evt.getRemoteAddress());

	}

	private int computeBlockSequenceNumber(ChannelHandlerContext ctx) {
		int blockCounter = getAndIncrementBlockSequenceCounter(ctx);
		return (blockCounter % 10);
	}

	private int getAndIncrementBlockSequenceCounter(ChannelHandlerContext ctx) {
		AtomicInteger blockSequenceCounter = (AtomicInteger) ctx.getAttachment();
		if (blockSequenceCounter == null) {
			blockSequenceCounter = new AtomicInteger(0);
			ctx.setAttachment(blockSequenceCounter);
		}
		return blockSequenceCounter.getAndIncrement();
	}

}
