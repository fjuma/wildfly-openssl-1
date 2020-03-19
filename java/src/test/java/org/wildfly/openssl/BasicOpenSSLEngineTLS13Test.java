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

package org.wildfly.openssl;

import static org.wildfly.openssl.SSLTestUtils.HOST;
import static org.wildfly.openssl.SSLTestUtils.PORT;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class BasicOpenSSLEngineTLS13Test extends AbstractOpenSSLTest  {

    @Before
    public void testOpenSSLVersion() {
        Assume.assumeTrue(isTls13Supported());
    }

    public static final String MESSAGE = "Hello World";

    @Test
    public void basicOpenSSLTest() throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<String> protocol = new AtomicReference<>();
            final AtomicReference<String> cipherSuite = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.3");

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, null, protocol, cipherSuite));
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLTestUtils.createClientSSLContext("openssl.TLSv1.3").getSocketFactory().createSocket();//(SSLSocket) SSLSocketFactory.getDefault().createSocket();
            //SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            Assert.assertEquals("TLSv1.3", protocol.get());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(cipherSuite.get()));
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test(expected = SSLException.class)
    public void testWrongClientSideTrustManagerFailsValidation() throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<String> protocol = new AtomicReference<>();
            final AtomicReference<String> cipherSuite = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.3");

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, null, protocol, cipherSuite));
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLTestUtils.createSSLContext("openssl.TLSv1.3").getSocketFactory().createSocket();
            socket.setSSLParameters(socket.getSSLParameters());
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            Assert.assertEquals("TLSv1.3", protocol.get());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(cipherSuite.get()));
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }


    @Test
    public void openSslLotsOfDataTest() throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<String> protocol = new AtomicReference<>();
            final AtomicReference<String> cipherSuite = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.3");

            EchoRunnable target = new EchoRunnable(serverSocket, sslContext, sessionID, null, protocol, cipherSuite);
            Thread acceptThread = new Thread(target);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            String message = generateMessage(1000);
            socket.getOutputStream().write(message.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(new byte[]{0});

            Assert.assertEquals(message, new String(SSLTestUtils.readData(socket.getInputStream())));
            Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            Assert.assertEquals("TLSv1.3", protocol.get());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(cipherSuite.get()));

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testNoExplicitEnabledProtocols() throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final AtomicReference<String> protocol = new AtomicReference<>();
            final AtomicReference<String> cipherSuite = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.3");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }), protocol, cipherSuite);
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            Assert.assertEquals("TLSv1.3", protocol.get());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(cipherSuite.get()));
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testTwoWay() throws Exception {
        final SSLContext serverContext = SSLTestUtils.createSSLContext("openssl.TLSv1.3");
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<SSLSocket> socketFuture = executorService.submit(() -> {
            try {
                SSLContext clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1.3");
                SSLSocket sslSocket = (SSLSocket) clientContext.getSocketFactory().createSocket(HOST, PORT);
                sslSocket.getSession();
                return sslSocket;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        SSLServerSocket sslServerSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(PORT, 10, InetAddress.getByName(HOST));
        SSLSocket serverSocket = (SSLSocket) sslServerSocket.accept();
        SSLSession serverSession = serverSocket.getSession();
        SSLSocket clientSocket = socketFuture.get();
        SSLSession clientSession = clientSocket.getSession();

        try {
            Assert.assertEquals("TLSv1.3", clientSession.getProtocol());
            Assert.assertEquals("TLSv1.3", serverSession.getProtocol());
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(clientSession.getCipherSuite()));
            Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(serverSession.getCipherSuite()));
        } finally {
            serverSocket.close();
            clientSocket.close();
            sslServerSocket.close();
        }

    }

    private static String generateMessage(int repetitions) {
        final StringBuilder builder = new StringBuilder(repetitions * MESSAGE.length());
        for (int i = 0; i < repetitions; ++i) {
            builder.append(MESSAGE);
        }
        return builder.toString();
    }
}
