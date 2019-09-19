/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nginx.unit.websocket.server;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
import java.nio.channels.InterruptedByTimeoutException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import javax.websocket.SendHandler;
import javax.websocket.SendResult;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;
import nginx.unit.websocket.Transformation;
import nginx.unit.websocket.WsRemoteEndpointImplBase;

/**
 * This is the server side {@link javax.websocket.RemoteEndpoint} implementation
 * - i.e. what the server uses to send data to the client.
 */
public class WsRemoteEndpointImplServer extends WsRemoteEndpointImplBase {

    private static final StringManager sm =
            StringManager.getManager(WsRemoteEndpointImplServer.class);
    private final Log log = LogFactory.getLog(WsRemoteEndpointImplServer.class); // must not be static

    private volatile SendHandler handler = null;
    private volatile ByteBuffer[] buffers = null;

    private volatile long timeoutExpiry = -1;
    private volatile boolean close;

    public WsRemoteEndpointImplServer(
            WsServerContainer serverContainer) {
    }


    @Override
    protected final boolean isMasked() {
        return false;
    }

    @Override
    protected void doWrite(SendHandler handler, long blockingWriteTimeoutExpiry,
            ByteBuffer... buffers) {
    }

    @Override
    protected void doClose() {
        if (handler != null) {
            // close() can be triggered by a wide range of scenarios. It is far
            // simpler just to always use a dispatch than it is to try and track
            // whether or not this method was called by the same thread that
            // triggered the write
            clearHandler(new EOFException(), true);
        }
    }


    protected long getTimeoutExpiry() {
        return timeoutExpiry;
    }


    /*
     * Currently this is only called from the background thread so we could just
     * call clearHandler() with useDispatch == false but the method parameter
     * was added in case other callers started to use this method to make sure
     * that those callers think through what the correct value of useDispatch is
     * for them.
     */
    protected void onTimeout(boolean useDispatch) {
        if (handler != null) {
            clearHandler(new SocketTimeoutException(), useDispatch);
        }
        close();
    }


    @Override
    protected void setTransformation(Transformation transformation) {
        // Overridden purely so it is visible to other classes in this package
        super.setTransformation(transformation);
    }


    /**
     *
     * @param t             The throwable associated with any error that
     *                      occurred
     * @param useDispatch   Should {@link SendHandler#onResult(SendResult)} be
     *                      called from a new thread, keeping in mind the
     *                      requirements of
     *                      {@link javax.websocket.RemoteEndpoint.Async}
     */
    private void clearHandler(Throwable t, boolean useDispatch) {
        // Setting the result marks this (partial) message as
        // complete which means the next one may be sent which
        // could update the value of the handler. Therefore, keep a
        // local copy before signalling the end of the (partial)
        // message.
        SendHandler sh = handler;
        handler = null;
        buffers = null;
        if (sh != null) {
            if (useDispatch) {
                OnResultRunnable r = new OnResultRunnable(sh, t);
            } else {
                if (t == null) {
                    sh.onResult(new SendResult());
                } else {
                    sh.onResult(new SendResult(t));
                }
            }
        }
    }


    private static class OnResultRunnable implements Runnable {

        private final SendHandler sh;
        private final Throwable t;

        private OnResultRunnable(SendHandler sh, Throwable t) {
            this.sh = sh;
            this.t = t;
        }

        @Override
        public void run() {
            if (t == null) {
                sh.onResult(new SendResult());
            } else {
                sh.onResult(new SendResult(t));
            }
        }
    }
}
