/*******************************************************************************
 * Copyright (c) 2019-2022 Oak Ridge National Laboratory.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 ******************************************************************************/
package org.epics.pva.server;

import static org.epics.pva.PVASettings.logger;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.List;
import java.util.logging.Level;

import org.epics.pva.common.CommandHandlers;
import org.epics.pva.common.PVAHeader;
import org.epics.pva.common.RequestEncoder;
import org.epics.pva.common.SearchResponse;
import org.epics.pva.common.TCPHandler;
import org.epics.pva.data.PVASize;
import org.epics.pva.data.PVAString;
import org.epics.pva.data.PVATypeRegistry;

/** Handler for one TCP-connected client
 *  @author Kay Kasemir
 */
@SuppressWarnings("nls")
class ServerTCPHandler extends TCPHandler
{
    /** Handlers for various commands, re-used whenever a command is received */
    private static final CommandHandlers<ServerTCPHandler> handlers =
        new CommandHandlers<>(new ValidationHandler(),
                              new SearchCommandHandler(),
                              new EchoHandler(),
                              new CreateChannelHandler(),
                              new GetHandler(),
                              new PutHandler(),
                              new MonitorHandler(),
                              new DestroyChannelHandler(),
                              new GetTypeHandler(),
                              new DestroyRequestHandler(),
                              new RPCHandler(),
                              new CancelHandler());

    /** Server that holds all the PVs */
    private final PVAServer server;

    /** Types declared by client at other end of this TCP connection */
    private final PVATypeRegistry client_types = new PVATypeRegistry();

    /** Auth info, e.g. client user info and his/her permissions */
    private volatile ServerAuth auth = ServerAuth.Anonymous;

    public ServerTCPHandler(final PVAServer server, final SocketChannel client) throws Exception
    {
        super(client, false);
        this.server = server;
        server.register(this);
        startSender();

        // Initialize TCP connection by setting byte order..
        submit((version, buffer) ->
        {
            logger.log(Level.FINE, () -> "Set byte order " + buffer.order());
            // Payload size is used as byte order hint
            // 0xFFFFFFFF: Client needs to check each message for byte order
            // 0x00000000: Server sends each message in the same byte order,
            //             but there's still a valid byte order flag,
            //             so client is free to keep checking each message
            final int size_used_as_hint = 0x00000000;
            PVAHeader.encodeMessageHeader(buffer,
                    (byte) (PVAHeader.FLAG_CONTROL | PVAHeader.FLAG_SERVER),
                    PVAHeader.CTRL_SET_BYTE_ORDER, size_used_as_hint);
        });
        // .. and requesting connection validation
        submit((version, buffer) ->
        {
            logger.log(Level.FINE, () -> "Sending Validation Request");
            PVAHeader.encodeMessageHeader(buffer,
                    PVAHeader.FLAG_SERVER,
                    PVAHeader.CMD_CONNECTION_VALIDATION, 4+2+1+PVAString.getEncodedSize("anonymous") + PVAString.getEncodedSize("ca"));

            // int serverReceiveBufferSize;
            buffer.putInt(receive_buffer.capacity());

            // short serverIntrospectionRegistryMaxSize;
            buffer.putShort(Short.MAX_VALUE);

            // string[] authNZ;
            PVASize.encodeSize(1, buffer);

            // TODO ServerAuthentication
            PVAString.encodeString("ca", buffer);
            PVAString.encodeString("anonymous", buffer);
        });
    }

    PVAServer getServer()
    {
        return server;
    }

    PVATypeRegistry getClientTypes()
    {
        return client_types;
    }

    void setAuth(final ServerAuth auth)
    {
        this.auth = auth;
    }

    // XXX At this time, nothing uses the auth info
    ServerAuth getAuth()
    {
        return auth;
    }

    @Override
    protected void onReceiverExited(final boolean running)
    {
        if (running)
            server.shutdownConnection(this);
    }

    @Override
    protected void handleControlMessage(final byte command, final ByteBuffer buffer) throws Exception
    {
        if (command == PVAHeader.CTRL_SET_BYTE_ORDER)
            logger.log(Level.WARNING, "Client sent SET_BYTE_ORDER command?");
        else
            super.handleControlMessage(command, buffer);
    }

    @Override
    protected void handleApplicationMessage(final byte command, final ByteBuffer buffer) throws Exception
    {
        if (!handlers.handleCommand(command, this, buffer))
            super.handleApplicationMessage(command, buffer);
    }

    void submitSearchReply(final Guid guid, final int seq, final int cid, final InetSocketAddress server_address, final List<String> protocols)
    {
        final RequestEncoder encoder = (version, buffer) ->
        {
            logger.log(Level.FINER, "Sending TCP search reply");
            SearchResponse.encode(guid, seq, cid, server_address.getAddress(), server_address.getPort(), buffer, protocols);
        };
        submit(encoder);
    }
}
