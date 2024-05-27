/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nginx.unit.websocket;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.channels.WritePendingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.websocket.CloseReason;
import javax.websocket.CloseReason.CloseCode;
import javax.websocket.CloseReason.CloseCodes;
import javax.websocket.DeploymentException;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.Extension;
import javax.websocket.MessageHandler;
import javax.websocket.MessageHandler.Partial;
import javax.websocket.MessageHandler.Whole;
import javax.websocket.PongMessage;
import javax.websocket.RemoteEndpoint;
import javax.websocket.SendResult;
import javax.websocket.Session;
import javax.websocket.WebSocketContainer;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.InstanceManager;
import org.apache.tomcat.InstanceManagerBindings;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.buf.Utf8Decoder;
import org.apache.tomcat.util.res.StringManager;

import nginx.unit.Request;

public class WsSession implements Session {

    // An ellipsis is a single character that looks like three periods in a row
    // and is used to indicate a continuation.
    private static final byte[] ELLIPSIS_BYTES = "\u2026".getBytes(StandardCharsets.UTF_8);
    // An ellipsis is three bytes in UTF-8
    private static final int ELLIPSIS_BYTES_LEN = ELLIPSIS_BYTES.length;

    private static final StringManager sm = StringManager.getManager(WsSession.class);
    private static AtomicLong ids = new AtomicLong(0);

    private final Log log = LogFactory.getLog(WsSession.class); // must not be static

    private final CharsetDecoder utf8DecoderMessage = new Utf8Decoder().
            onMalformedInput(CodingErrorAction.REPORT).
            onUnmappableCharacter(CodingErrorAction.REPORT);

    private final Endpoint localEndpoint;
    private final WsRemoteEndpointImplBase wsRemoteEndpoint;
    private final RemoteEndpoint.Async remoteEndpointAsync;
    private final RemoteEndpoint.Basic remoteEndpointBasic;
    private final ClassLoader applicationClassLoader;
    private final WsWebSocketContainer webSocketContainer;
    private final URI requestUri;
    private final Map<String, List<String>> requestParameterMap;
    private final String queryString;
    private final Principal userPrincipal;
    private final EndpointConfig endpointConfig;

    private final List<Extension> negotiatedExtensions;
    private final String subProtocol;
    private final Map<String, String> pathParameters;
    private final boolean secure;
    private final String httpSessionId;
    private final String id;

    // Expected to handle message types of <String> only
    private volatile MessageHandler textMessageHandler = null;
    // Expected to handle message types of <ByteBuffer> only
    private volatile MessageHandler binaryMessageHandler = null;
    private volatile MessageHandler.Whole<PongMessage> pongMessageHandler = null;
    private volatile State state = State.OPEN;
    private final Object stateLock = new Object();
    private final Map<String, Object> userProperties = new ConcurrentHashMap<>();
    private volatile int maxBinaryMessageBufferSize = Constants.DEFAULT_BUFFER_SIZE;
    private volatile int maxTextMessageBufferSize = Constants.DEFAULT_BUFFER_SIZE;
    private volatile long maxIdleTimeout = 0;
    private volatile long lastActive = System.currentTimeMillis();
    private Map<FutureToSendHandler, FutureToSendHandler> futures = new ConcurrentHashMap<>();

    private CharBuffer messageBufferText;
    private ByteBuffer binaryBuffer;
    private byte startOpCode = Constants.OPCODE_CONTINUATION;

    /**
     * Creates a new WebSocket session for communication between the two
     * provided end points. The result of {@link Thread#getContextClassLoader()}
     * at the time this constructor is called will be used when calling
     * {@link Endpoint#onClose(Session, CloseReason)}.
     *
     * @param localEndpoint        The end point managed by this code
     * @param wsRemoteEndpoint     The other / remote endpoint
     * @param wsWebSocketContainer The container that created this session
     * @param requestUri           The URI used to connect to this endpoint or
     *                             <code>null</code> is this is a client session
     * @param requestParameterMap  The parameters associated with the request
     *                             that initiated this session or
     *                             <code>null</code> if this is a client session
     * @param queryString          The query string associated with the request
     *                             that initiated this session or
     *                             <code>null</code> if this is a client session
     * @param userPrincipal        The principal associated with the request
     *                             that initiated this session or
     *                             <code>null</code> if this is a client session
     * @param httpSessionId        The HTTP session ID associated with the
     *                             request that initiated this session or
     *                             <code>null</code> if this is a client session
     * @param negotiatedExtensions The agreed extensions to use for this session
     * @param subProtocol          The agreed subprotocol to use for this
     *                             session
     * @param pathParameters       The path parameters associated with the
     *                             request that initiated this session or
     *                             <code>null</code> if this is a client session
     * @param secure               Was this session initiated over a secure
     *                             connection?
     * @param endpointConfig       The configuration information for the
     *                             endpoint
     * @throws DeploymentException if an invalid encode is specified
     */
    public WsSession(Endpoint localEndpoint,
            WsRemoteEndpointImplBase wsRemoteEndpoint,
            WsWebSocketContainer wsWebSocketContainer,
            URI requestUri, Map<String, List<String>> requestParameterMap,
            String queryString, Principal userPrincipal, String httpSessionId,
            List<Extension> negotiatedExtensions, String subProtocol, Map<String, String> pathParameters,
            boolean secure, EndpointConfig endpointConfig,
            Request request) throws DeploymentException {
        this.localEndpoint = localEndpoint;
        this.wsRemoteEndpoint = wsRemoteEndpoint;
        this.wsRemoteEndpoint.setSession(this);
        this.wsRemoteEndpoint.setRequest(request);

        request.setWsSession(this);

        this.remoteEndpointAsync = new WsRemoteEndpointAsync(wsRemoteEndpoint);
        this.remoteEndpointBasic = new WsRemoteEndpointBasic(wsRemoteEndpoint);
        this.webSocketContainer = wsWebSocketContainer;
        applicationClassLoader = Thread.currentThread().getContextClassLoader();
        wsRemoteEndpoint.setSendTimeout(wsWebSocketContainer.getDefaultAsyncSendTimeout());
        this.maxBinaryMessageBufferSize = webSocketContainer.getDefaultMaxBinaryMessageBufferSize();
        this.maxTextMessageBufferSize = webSocketContainer.getDefaultMaxTextMessageBufferSize();
        this.maxIdleTimeout = webSocketContainer.getDefaultMaxSessionIdleTimeout();
        this.requestUri = requestUri;
        if (requestParameterMap == null) {
            this.requestParameterMap = Collections.emptyMap();
        } else {
            this.requestParameterMap = requestParameterMap;
        }
        this.queryString = queryString;
        this.userPrincipal = userPrincipal;
        this.httpSessionId = httpSessionId;
        this.negotiatedExtensions = negotiatedExtensions;
        if (subProtocol == null) {
            this.subProtocol = "";
        } else {
            this.subProtocol = subProtocol;
        }
        this.pathParameters = pathParameters;
        this.secure = secure;
        this.wsRemoteEndpoint.setEncoders(endpointConfig);
        this.endpointConfig = endpointConfig;

        this.userProperties.putAll(endpointConfig.getUserProperties());
        this.id = Long.toHexString(ids.getAndIncrement());

        InstanceManager instanceManager = webSocketContainer.getInstanceManager();
        if (instanceManager == null) {
            instanceManager = InstanceManagerBindings.get(applicationClassLoader);
        }
        if (instanceManager != null) {
            try {
                instanceManager.newInstance(localEndpoint);
            } catch (Exception e) {
                throw new DeploymentException(sm.getString("wsSession.instanceNew"), e);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug(sm.getString("wsSession.created", id));
        }

        messageBufferText = CharBuffer.allocate(maxTextMessageBufferSize);
    }

    public static String wsSession_test() {
        return sm.getString("wsSession.instanceNew");
    }


    @Override
    public WebSocketContainer getContainer() {
        checkState();
        return webSocketContainer;
    }


    @Override
    public void addMessageHandler(MessageHandler listener) {
        Class<?> target = Util.getMessageType(listener);
        doAddMessageHandler(target, listener);
    }


    @Override
    public <T> void addMessageHandler(Class<T> clazz, Partial<T> handler)
            throws IllegalStateException {
        doAddMessageHandler(clazz, handler);
    }


    @Override
    public <T> void addMessageHandler(Class<T> clazz, Whole<T> handler)
            throws IllegalStateException {
        doAddMessageHandler(clazz, handler);
    }


    @SuppressWarnings("unchecked")
    private void doAddMessageHandler(Class<?> target, MessageHandler listener) {
        checkState();

        // Message handlers that require decoders may map to text messages,
        // binary messages, both or neither.

        // The frame processing code expects binary message handlers to
        // accept ByteBuffer

        // Use the POJO message handler wrappers as they are designed to wrap
        // arbitrary objects with MessageHandlers and can wrap MessageHandlers
        // just as easily.

        Set<MessageHandlerResult> mhResults = Util.getMessageHandlers(target, listener,
                endpointConfig, this);

        for (MessageHandlerResult mhResult : mhResults) {
            switch (mhResult.getType()) {
            case TEXT: {
                if (textMessageHandler != null) {
                    throw new IllegalStateException(sm.getString("wsSession.duplicateHandlerText"));
                }
                textMessageHandler = mhResult.getHandler();
                break;
            }
            case BINARY: {
                if (binaryMessageHandler != null) {
                    throw new IllegalStateException(
                            sm.getString("wsSession.duplicateHandlerBinary"));
                }
                binaryMessageHandler = mhResult.getHandler();
                break;
            }
            case PONG: {
                if (pongMessageHandler != null) {
                    throw new IllegalStateException(sm.getString("wsSession.duplicateHandlerPong"));
                }
                MessageHandler handler = mhResult.getHandler();
                if (handler instanceof MessageHandler.Whole<?>) {
                    pongMessageHandler = (MessageHandler.Whole<PongMessage>) handler;
                } else {
                    throw new IllegalStateException(
                            sm.getString("wsSession.invalidHandlerTypePong"));
                }

                break;
            }
            default: {
                throw new IllegalArgumentException(
                        sm.getString("wsSession.unknownHandlerType", listener, mhResult.getType()));
            }
            }
        }
    }


    @Override
    public Set<MessageHandler> getMessageHandlers() {
        checkState();
        Set<MessageHandler> result = new HashSet<>();
        if (binaryMessageHandler != null) {
            result.add(binaryMessageHandler);
        }
        if (textMessageHandler != null) {
            result.add(textMessageHandler);
        }
        if (pongMessageHandler != null) {
            result.add(pongMessageHandler);
        }
        return result;
    }


    @Override
    public void removeMessageHandler(MessageHandler listener) {
        checkState();
        if (listener == null) {
            return;
        }

        MessageHandler wrapped = null;

        if (listener instanceof WrappedMessageHandler) {
            wrapped = ((WrappedMessageHandler) listener).getWrappedHandler();
        }

        if (wrapped == null) {
            wrapped = listener;
        }

        boolean removed = false;
        if (wrapped.equals(textMessageHandler) || listener.equals(textMessageHandler)) {
            textMessageHandler = null;
            removed = true;
        }

        if (wrapped.equals(binaryMessageHandler) || listener.equals(binaryMessageHandler)) {
            binaryMessageHandler = null;
            removed = true;
        }

        if (wrapped.equals(pongMessageHandler) || listener.equals(pongMessageHandler)) {
            pongMessageHandler = null;
            removed = true;
        }

        if (!removed) {
            // ISE for now. Could swallow this silently / log this if the ISE
            // becomes a problem
            throw new IllegalStateException(
                    sm.getString("wsSession.removeHandlerFailed", listener));
        }
    }


    @Override
    public String getProtocolVersion() {
        checkState();
        return Constants.WS_VERSION_HEADER_VALUE;
    }


    @Override
    public String getNegotiatedSubprotocol() {
        checkState();
        return subProtocol;
    }


    @Override
    public List<Extension> getNegotiatedExtensions() {
        checkState();
        return negotiatedExtensions;
    }


    @Override
    public boolean isSecure() {
        checkState();
        return secure;
    }


    @Override
    public boolean isOpen() {
        return state == State.OPEN;
    }


    @Override
    public long getMaxIdleTimeout() {
        checkState();
        return maxIdleTimeout;
    }


    @Override
    public void setMaxIdleTimeout(long timeout) {
        checkState();
        this.maxIdleTimeout = timeout;
    }


    @Override
    public void setMaxBinaryMessageBufferSize(int max) {
        checkState();
        this.maxBinaryMessageBufferSize = max;
    }


    @Override
    public int getMaxBinaryMessageBufferSize() {
        checkState();
        return maxBinaryMessageBufferSize;
    }


    @Override
    public void setMaxTextMessageBufferSize(int max) {
        checkState();
        this.maxTextMessageBufferSize = max;
    }


    @Override
    public int getMaxTextMessageBufferSize() {
        checkState();
        return maxTextMessageBufferSize;
    }


    @Override
    public Set<Session> getOpenSessions() {
        checkState();
        return webSocketContainer.getOpenSessions(localEndpoint);
    }


    @Override
    public RemoteEndpoint.Async getAsyncRemote() {
        checkState();
        return remoteEndpointAsync;
    }


    @Override
    public RemoteEndpoint.Basic getBasicRemote() {
        checkState();
        return remoteEndpointBasic;
    }


    @Override
    public void close() throws IOException {
        close(new CloseReason(CloseCodes.NORMAL_CLOSURE, ""));
    }


    @Override
    public void close(CloseReason closeReason) throws IOException {
        doClose(closeReason, closeReason);
    }


    /**
     * WebSocket 1.0. Section 2.1.5.
     * Need internal close method as spec requires that the local endpoint
     * receives a 1006 on timeout.
     *
     * @param closeReasonMessage The close reason to pass to the remote endpoint
     * @param closeReasonLocal   The close reason to pass to the local endpoint
     */
    public void doClose(CloseReason closeReasonMessage, CloseReason closeReasonLocal) {
        // Double-checked locking. OK because state is volatile
        if (state != State.OPEN) {
            return;
        }

        synchronized (stateLock) {
            if (state != State.OPEN) {
                return;
            }

            if (log.isDebugEnabled()) {
                log.debug(sm.getString("wsSession.doClose", id));
            }
            try {
                wsRemoteEndpoint.setBatchingAllowed(false);
            } catch (IOException e) {
                log.warn(sm.getString("wsSession.flushFailOnClose"), e);
                fireEndpointOnError(e);
            }

            state = State.OUTPUT_CLOSED;

            sendCloseMessage(closeReasonMessage);
            fireEndpointOnClose(closeReasonLocal);
        }

        IOException ioe = new IOException(sm.getString("wsSession.messageFailed"));
        SendResult sr = new SendResult(ioe);
        for (FutureToSendHandler f2sh : futures.keySet()) {
            f2sh.onResult(sr);
        }
    }


    /**
     * Called when a close message is received. Should only ever happen once.
     * Also called after a protocol error when the ProtocolHandler needs to
     * force the closing of the connection.
     *
     * @param closeReason The reason contained within the received close
     *                    message.
     */
    public void onClose(CloseReason closeReason) {

        synchronized (stateLock) {
            if (state != State.CLOSED) {
                try {
                    wsRemoteEndpoint.setBatchingAllowed(false);
                } catch (IOException e) {
                    log.warn(sm.getString("wsSession.flushFailOnClose"), e);
                    fireEndpointOnError(e);
                }
                if (state == State.OPEN) {
                    state = State.OUTPUT_CLOSED;
                    sendCloseMessage(closeReason);
                    fireEndpointOnClose(closeReason);
                }
                state = State.CLOSED;

                // Close the socket
                wsRemoteEndpoint.close();
            }
        }
    }


    public void onClose() {

        synchronized (stateLock) {
            if (state != State.CLOSED) {
                try {
                    wsRemoteEndpoint.setBatchingAllowed(false);
                } catch (IOException e) {
                    log.warn(sm.getString("wsSession.flushFailOnClose"), e);
                    fireEndpointOnError(e);
                }
                if (state == State.OPEN) {
                    state = State.OUTPUT_CLOSED;
                    fireEndpointOnClose(new CloseReason(
                        CloseReason.CloseCodes.NORMAL_CLOSURE, ""));
                }
                state = State.CLOSED;

                // Close the socket
                wsRemoteEndpoint.close();
            }
        }
    }


    private void fireEndpointOnClose(CloseReason closeReason) {

        // Fire the onClose event
        Throwable throwable = null;
        InstanceManager instanceManager = webSocketContainer.getInstanceManager();
        if (instanceManager == null) {
            instanceManager = InstanceManagerBindings.get(applicationClassLoader);
        }
        Thread t = Thread.currentThread();
        ClassLoader cl = t.getContextClassLoader();
        t.setContextClassLoader(applicationClassLoader);
        try {
            localEndpoint.onClose(this, closeReason);
        } catch (Throwable t1) {
            ExceptionUtils.handleThrowable(t1);
            throwable = t1;
        } finally {
            if (instanceManager != null) {
                try {
                    instanceManager.destroyInstance(localEndpoint);
                } catch (Throwable t2) {
                    ExceptionUtils.handleThrowable(t2);
                    if (throwable == null) {
                        throwable = t2;
                    }
                }
            }
            t.setContextClassLoader(cl);
        }

        if (throwable != null) {
            fireEndpointOnError(throwable);
        }
    }


    private void fireEndpointOnError(Throwable throwable) {

        // Fire the onError event
        Thread t = Thread.currentThread();
        ClassLoader cl = t.getContextClassLoader();
        t.setContextClassLoader(applicationClassLoader);
        try {
            localEndpoint.onError(this, throwable);
        } finally {
            t.setContextClassLoader(cl);
        }
    }


    private void sendCloseMessage(CloseReason closeReason) {
        // 125 is maximum size for the payload of a control message
        ByteBuffer msg = ByteBuffer.allocate(125);
        CloseCode closeCode = closeReason.getCloseCode();
        // CLOSED_ABNORMALLY should not be put on the wire
        if (closeCode == CloseCodes.CLOSED_ABNORMALLY) {
            // PROTOCOL_ERROR is probably better than GOING_AWAY here
            msg.putShort((short) CloseCodes.PROTOCOL_ERROR.getCode());
        } else {
            msg.putShort((short) closeCode.getCode());
        }

        String reason = closeReason.getReasonPhrase();
        if (reason != null && reason.length() > 0) {
            appendCloseReasonWithTruncation(msg, reason);
        }
        msg.flip();
        try {
            wsRemoteEndpoint.sendMessageBlock(Constants.OPCODE_CLOSE, msg, true);
        } catch (IOException | WritePendingException e) {
            // Failed to send close message. Close the socket and let the caller
            // deal with the Exception
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("wsSession.sendCloseFail", id), e);
            }
            wsRemoteEndpoint.close();
            // Failure to send a close message is not unexpected in the case of
            // an abnormal closure (usually triggered by a failure to read/write
            // from/to the client. In this case do not trigger the endpoint's
            // error handling
            if (closeCode != CloseCodes.CLOSED_ABNORMALLY) {
                localEndpoint.onError(this, e);
            }
        } finally {
            webSocketContainer.unregisterSession(localEndpoint, this);
        }
    }


    /**
     * Use protected so unit tests can access this method directly.
     * @param msg The message
     * @param reason The reason
     */
    protected static void appendCloseReasonWithTruncation(ByteBuffer msg, String reason) {
        // Once the close code has been added there are a maximum of 123 bytes
        // left for the reason phrase. If it is truncated then care needs to be
        // taken to ensure the bytes are not truncated in the middle of a
        // multi-byte UTF-8 character.
        byte[] reasonBytes = reason.getBytes(StandardCharsets.UTF_8);

        if (reasonBytes.length <= 123) {
            // No need to truncate
            msg.put(reasonBytes);
        } else {
            // Need to truncate
            int remaining = 123 - ELLIPSIS_BYTES_LEN;
            int pos = 0;
            byte[] bytesNext = reason.substring(pos, pos + 1).getBytes(StandardCharsets.UTF_8);
            while (remaining >= bytesNext.length) {
                msg.put(bytesNext);
                remaining -= bytesNext.length;
                pos++;
                bytesNext = reason.substring(pos, pos + 1).getBytes(StandardCharsets.UTF_8);
            }
            msg.put(ELLIPSIS_BYTES);
        }
    }


    /**
     * Make the session aware of a {@link FutureToSendHandler} that will need to
     * be forcibly closed if the session closes before the
     * {@link FutureToSendHandler} completes.
     * @param f2sh The handler
     */
    protected void registerFuture(FutureToSendHandler f2sh) {
        // Ideally, this code should sync on stateLock so that the correct
        // action is taken based on the current state of the connection.
        // However, a sync on stateLock can't be used here as it will create the
        // possibility of a dead-lock. See BZ 61183.
        // Therefore, a slightly less efficient approach is used.

        // Always register the future.
        futures.put(f2sh, f2sh);

        if (state == State.OPEN) {
            // The session is open. The future has been registered with the open
            // session. Normal processing continues.
            return;
        }

        // The session is closed. The future may or may not have been registered
        // in time for it to be processed during session closure.

        if (f2sh.isDone()) {
            // The future has completed. It is not known if the future was
            // completed normally by the I/O layer or in error by doClose(). It
            // doesn't matter which. There is nothing more to do here.
            return;
        }

        // The session is closed. The Future had not completed when last checked.
        // There is a small timing window that means the Future may have been
        // completed since the last check. There is also the possibility that
        // the Future was not registered in time to be cleaned up during session
        // close.
        // Attempt to complete the Future with an error result as this ensures
        // that the Future completes and any client code waiting on it does not
        // hang. It is slightly inefficient since the Future may have been
        // completed in another thread or another thread may be about to
        // complete the Future but knowing if this is the case requires the sync
        // on stateLock (see above).
        // Note: If multiple attempts are made to complete the Future, the
        //       second and subsequent attempts are ignored.

        IOException ioe = new IOException(sm.getString("wsSession.messageFailed"));
        SendResult sr = new SendResult(ioe);
        f2sh.onResult(sr);
    }


    /**
     * Remove a {@link FutureToSendHandler} from the set of tracked instances.
     * @param f2sh The handler
     */
    protected void unregisterFuture(FutureToSendHandler f2sh) {
        futures.remove(f2sh);
    }


    @Override
    public URI getRequestURI() {
        checkState();
        return requestUri;
    }


    @Override
    public Map<String, List<String>> getRequestParameterMap() {
        checkState();
        return requestParameterMap;
    }


    @Override
    public String getQueryString() {
        checkState();
        return queryString;
    }


    @Override
    public Principal getUserPrincipal() {
        checkState();
        return userPrincipal;
    }


    @Override
    public Map<String, String> getPathParameters() {
        checkState();
        return pathParameters;
    }


    @Override
    public String getId() {
        return id;
    }


    @Override
    public Map<String, Object> getUserProperties() {
        checkState();
        return userProperties;
    }


    public Endpoint getLocal() {
        return localEndpoint;
    }


    public String getHttpSessionId() {
        return httpSessionId;
    }

    private ByteBuffer rawFragments;

    public void processFrame(ByteBuffer buf, byte opCode, boolean last)
        throws IOException
    {
        if (state == State.CLOSED) {
            return;
        }

        if (opCode == Constants.OPCODE_CONTINUATION) {
            opCode = startOpCode;

            if (rawFragments != null && rawFragments.position() > 0) {
                rawFragments.put(buf);
                rawFragments.flip();
                buf = rawFragments;
            }
        } else {
            if (!last && (opCode == Constants.OPCODE_BINARY ||
                          opCode == Constants.OPCODE_TEXT)) {
                startOpCode = opCode;

                if (rawFragments != null) {
                    rawFragments.clear();
                }
            }
        }

        if (last) {
            startOpCode = Constants.OPCODE_CONTINUATION;
        }

        if (opCode == Constants.OPCODE_PONG) {
            if (pongMessageHandler != null) {
                final ByteBuffer b = buf;

                PongMessage pongMessage = new PongMessage() {
                    @Override
                    public ByteBuffer getApplicationData() {
                        return b;
                    }
                };

                pongMessageHandler.onMessage(pongMessage);
            }
        }

        if (opCode == Constants.OPCODE_CLOSE) {
            CloseReason closeReason;

            if (buf.remaining() >= 2) {
                short closeCode = buf.order(ByteOrder.BIG_ENDIAN).getShort();

                closeReason = new CloseReason(
                    CloseReason.CloseCodes.getCloseCode(closeCode),
                    buf.asCharBuffer().toString());
            } else {
                closeReason = new CloseReason(
                    CloseReason.CloseCodes.NORMAL_CLOSURE, "");
            }

            onClose(closeReason);
        }

        if (opCode == Constants.OPCODE_BINARY) {
            onMessage(buf, last);
        }

        if (opCode == Constants.OPCODE_TEXT) {
            if (messageBufferText.position() == 0 && maxTextMessageBufferSize != messageBufferText.capacity()) {
                messageBufferText = CharBuffer.allocate(maxTextMessageBufferSize);
            }

            CoderResult cr = utf8DecoderMessage.decode(buf, messageBufferText, last);
            if (cr.isError()) {
                throw new WsIOException(new CloseReason(
                        CloseCodes.NOT_CONSISTENT,
                        sm.getString("wsFrame.invalidUtf8")));
            } else if (cr.isOverflow()) {
                // Ran out of space in text buffer - flush it
                if (hasTextPartial()) {
                    do {
                        onMessage(messageBufferText, false);

                        cr = utf8DecoderMessage.decode(buf, messageBufferText, last);
                    } while (cr.isOverflow());
                } else {
                    throw new WsIOException(new CloseReason(
                            CloseCodes.TOO_BIG,
                            sm.getString("wsFrame.textMessageTooBig")));
                }
            } else if (cr.isUnderflow() && !last) {
                updateRawFragments(buf, last);

                if (hasTextPartial()) {
                    onMessage(messageBufferText, false);
                }

                return;
            }

            if (last) {
                utf8DecoderMessage.reset();
            }

            updateRawFragments(buf, last);

            onMessage(messageBufferText, last);
        }
    }


    private boolean hasTextPartial() {
        return textMessageHandler instanceof MessageHandler.Partial<?>;
    }


    private void onMessage(CharBuffer buf, boolean last) throws IOException {
        buf.flip();
        try {
            onMessage(buf.toString(), last);
        } catch (Throwable t) {
            handleThrowableOnSend(t);
        } finally {
            buf.clear();
        }
    }


    private void updateRawFragments(ByteBuffer buf, boolean last) {
        if (!last && buf.remaining() > 0) {
            if (buf == rawFragments) {
                buf.compact();
            } else {
                if (rawFragments == null || (rawFragments.position() == 0 && maxTextMessageBufferSize != rawFragments.capacity())) {
                    rawFragments = ByteBuffer.allocateDirect(maxTextMessageBufferSize);
                }
                rawFragments.put(buf);
            }
        } else {
            if (rawFragments != null) {
                rawFragments.clear();
            }
        }
    }


    @SuppressWarnings("unchecked")
    public void onMessage(String text, boolean last) {
        if (hasTextPartial()) {
            ((MessageHandler.Partial<String>) textMessageHandler).onMessage(text, last);
        } else {
            // Caller ensures last == true if this branch is used
            ((MessageHandler.Whole<String>) textMessageHandler).onMessage(text);
        }
    }


    @SuppressWarnings("unchecked")
    public void onMessage(ByteBuffer buf, boolean last)
        throws IOException
    {
        if (binaryMessageHandler instanceof MessageHandler.Partial<?>) {
            ((MessageHandler.Partial<ByteBuffer>) binaryMessageHandler).onMessage(buf, last);
        } else {
            if (last && (binaryBuffer == null || binaryBuffer.position() == 0)) {
                ((MessageHandler.Whole<ByteBuffer>) binaryMessageHandler).onMessage(buf);
                return;
            }

            if (binaryBuffer == null ||
                (binaryBuffer.position() == 0 && binaryBuffer.capacity() != maxBinaryMessageBufferSize))
            {
                binaryBuffer = ByteBuffer.allocateDirect(maxBinaryMessageBufferSize);
            }

            if (binaryBuffer.remaining() < buf.remaining()) {
                throw new WsIOException(new CloseReason(
                        CloseCodes.TOO_BIG,
                        sm.getString("wsFrame.textMessageTooBig")));
            }

            binaryBuffer.put(buf);

            if (last) {
                binaryBuffer.flip();
                try {
                    ((MessageHandler.Whole<ByteBuffer>) binaryMessageHandler).onMessage(binaryBuffer);
                } finally {
                    binaryBuffer.clear();
                }
            }
        }
    }


    private void handleThrowableOnSend(Throwable t) throws WsIOException {
        ExceptionUtils.handleThrowable(t);
        getLocal().onError(this, t);
        CloseReason cr = new CloseReason(CloseCodes.CLOSED_ABNORMALLY,
                sm.getString("wsFrame.ioeTriggeredClose"));
        throw new WsIOException(cr);
    }


    protected MessageHandler getTextMessageHandler() {
        return textMessageHandler;
    }


    protected MessageHandler getBinaryMessageHandler() {
        return binaryMessageHandler;
    }


    protected MessageHandler.Whole<PongMessage> getPongMessageHandler() {
        return pongMessageHandler;
    }


    protected void updateLastActive() {
        lastActive = System.currentTimeMillis();
    }


    protected void checkExpiration() {
        long timeout = maxIdleTimeout;
        if (timeout < 1) {
            return;
        }

        if (System.currentTimeMillis() - lastActive > timeout) {
            String msg = sm.getString("wsSession.timeout", getId());
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            doClose(new CloseReason(CloseCodes.GOING_AWAY, msg),
                    new CloseReason(CloseCodes.CLOSED_ABNORMALLY, msg));
        }
    }


    private void checkState() {
        if (state == State.CLOSED) {
            /*
             * As per RFC 6455, a WebSocket connection is considered to be
             * closed once a peer has sent and received a WebSocket close frame.
             */
            throw new IllegalStateException(sm.getString("wsSession.closed", id));
        }
    }

    private enum State {
        OPEN,
        OUTPUT_CLOSED,
        CLOSED
    }
}
