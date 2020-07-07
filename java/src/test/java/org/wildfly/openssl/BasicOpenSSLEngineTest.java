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

import static org.wildfly.openssl.OpenSSLEngine.isOpenSSL10;
import static org.wildfly.openssl.OpenSSLEngine.isOpenSSL110FOrLower;
import static org.wildfly.openssl.SSL.SSL_PROTO_SSLv2Hello;
import static org.wildfly.openssl.SSLTestUtils.HOST;
import static org.wildfly.openssl.SSLTestUtils.PORT;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
public class BasicOpenSSLEngineTest extends AbstractOpenSSLTest  {

    public static final String MESSAGE = "Hello World";

    @Test
    public void basicOpenSSLTest() throws IOException, NoSuchAlgorithmException, InterruptedException {
        final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2" };
        for (String provider : providers) {
            basicTest(provider, provider);
        }
    }

    @Test
    public void basicOpenSSLTestTLS13() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        basicTest("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void basicOpenSSLTestInterop() throws IOException, NoSuchAlgorithmException, InterruptedException {
        final String[] providers = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String provider : providers) {
            basicTest("openssl." + provider, provider);
        }
        for (String provider : providers) {
            basicTest(provider, "openssl." + provider);
        }
    }

    @Test
    public void basicOpenSSLTestInteropTLS13() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        basicTest("openssl.TLSv1.3", "TLSv1.3");
        basicTest("TLSv1.3", "openssl.TLSv1.3");
    }

    private void basicTest(String serverProvider, String clientProvider) throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext(serverProvider);

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLTestUtils.createClientSSLContext(clientProvider).getSocketFactory().createSocket();
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! isTls13Supported()) {
                Assert.assertNotNull(socket.getSession().getId());
                if (sessionID.get() != null) {
                    // may be null with some older versions of OpenSSL (this assertion is also commented
                    // out in other existing tests)
                    Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                }
            }
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
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);
            SSLEngine sslEngine = engineRef.get();
            SSLSession session = sslEngine.getSession();

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! isTls13Supported()) {
                Assert.assertArrayEquals(sessionID.get(), socket.getSession().getId());
                Assert.assertEquals("TLSv1.2", socket.getSession().getProtocol());
                Assert.assertArrayEquals(sessionID.get(), session.getId());
                Assert.assertFalse(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            } else {
                Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
                Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            }
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testSingleEnabledProtocol() throws IOException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String protocol : protocols) {
            testSingleEnabledProtocolBase(protocol);
        }
    }

    @Test
    public void testSingleEnabledProtocolTLS13() throws IOException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        testSingleEnabledProtocolBase("TLSv1.3");
    }

    private void testSingleEnabledProtocolBase(String protocol) throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(new String[]{ protocol }); // only one protocol enabled on server side
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! protocol.equals("TLSv1.3")) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            }
            Assert.assertEquals(protocol, socket.getSession().getProtocol());
            Assert.assertEquals(protocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, protocol }, engineRef.get().getEnabledProtocols());
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testNoTLS13CipherSuitesEnabled() throws IOException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        testEnabledCipherSuites(new String[] { "ALL" }, false); // only enable TLS v1.2 cipher suites
    }

    @Test
    public void testBothTLS12AndTLS13CipherSuitesEnabled() throws IOException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        testEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256", "ALL" }, true);
    }

    @Test
    public void testTLS13CipherSuiteEnabled() throws IOException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        testEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" }, true);
    }

    @Test
    public void testTLS13UsedByDefault() throws IOException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        testEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" }, true);
    }


    private void testEnabledCipherSuites(String[] cipherSuites, boolean tls13Expected) throws IOException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    if (! tls13Expected) {
                        engine.setEnabledProtocols(new String[]{ "TLSv1.2"});
                    }
                    engine.setEnabledCipherSuites(cipherSuites);
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! tls13Expected) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                Assert.assertEquals("TLSv1.2", socket.getSession().getProtocol());
                Assert.assertEquals(false, CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            } else {
                Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
                Assert.assertEquals(true, CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
                Assert.assertEquals(cipherSuites[0], socket.getSession().getCipherSuite());
            }

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolExactMatch() throws IOException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1" };

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[] { "TLSv1" }); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1" }, engineRef.get().getEnabledProtocols());
            socket.getSession().invalidate();
            socket.close();

            socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[] { "TLSv1.1" }); // from list of enabled protocols on the server side
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            data = new byte[100];
            read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{ SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1"}, engineRef.get().getEnabledProtocols());

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolWithinEnabledRange() throws IOException, InterruptedException {
        Assume.assumeTrue(! isOpenSSL10() && ! isOpenSSL110FOrLower());
        final String[] protocols = new String[] { "TLSv1", "TLSv1.2" };

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(new String[] { "TLSv1.1" });
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            byte[] data = new byte[100];
            int read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            Assert.assertEquals("TLSv1.1", socket.getSession().getProtocol());
            Assert.assertArrayEquals(new String[]{SSL_PROTO_SSLv2Hello, "TLSv1", "TLSv1.1", "TLSv1.2"}, engineRef.get().getEnabledProtocols());

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testMultipleEnabledProtocolsWithClientProtocolOutsideOfEnabledRange() throws IOException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1.1", "TLSv1.2" };

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(protocols);
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(echo);
            acceptThread.start();

            SSLSocket socket = null;
            try {
                socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.setReuseAddress(true);
                socket.setEnabledProtocols(new String[]{"SSLv3"});
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
                if (socket != null) {
                    socket.close();
                }
            }
            try {
                socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                socket.setReuseAddress(true);
                socket.setEnabledProtocols(new String[]{"TLSv1"});
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLHandshakeException not thrown");
            } catch (SSLHandshakeException e) {
                // expected
                if (socket != null) {
                    socket.close();
                }
            }
            try {
                if (getJavaSpecVersion() >= 11) {
                    socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
                    socket.setReuseAddress(true);
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.connect(SSLTestUtils.createSocketAddress());
                    socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                    Assert.fail("Expected SSLHandshakeException not thrown");
                }
            } catch (SSLHandshakeException e) {
                // expected
                if (socket != null) {
                    socket.close();
                }
            }

            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testWrongClientSideTrustManagerFailsValidation() throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1");

            Thread acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLTestUtils.createSSLContext("openssl.TLSv1").getSocketFactory().createSocket();
            socket.setReuseAddress(true);
            socket.setSSLParameters(socket.getSSLParameters());
            socket.connect(SSLTestUtils.createSocketAddress());
            try {
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLException not thrown");
            } catch (SSLException expected) {
                socket.close();
                serverSocket.close();
                acceptThread.join();
            }
        }
    }


    @Test
    public void openSslLotsOfDataTest() throws IOException, NoSuchAlgorithmException, InterruptedException {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String protocol : protocols) {
            openSslLotsOfDataTestBase(protocol);
        }
    }

    @Test
    public void openSslLotsOfDataTestTLS13() throws IOException, NoSuchAlgorithmException, InterruptedException {
        Assume.assumeTrue(isTls13Supported());
        openSslLotsOfDataTestBase("TLSv1.3");
    }

    private void openSslLotsOfDataTestBase(String protocol) throws IOException, NoSuchAlgorithmException, InterruptedException {
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {
            final AtomicReference<byte[]> sessionID = new AtomicReference<>();
            final SSLContext sslContext = SSLTestUtils.createSSLContext("openssl.TLS");

            final AtomicReference<SSLEngine> engineRef = new AtomicReference<>();
            EchoRunnable target = new EchoRunnable(serverSocket, sslContext, sessionID, (engine -> {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(new String[]{ protocol }); // only one protocol enabled on server side
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            Thread acceptThread = new Thread(target);
            acceptThread.start();
            final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            String message = generateMessage(1000);
            socket.getOutputStream().write(message.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(new byte[]{0});

            Assert.assertEquals(message, new String(SSLTestUtils.readData(socket.getInputStream())));
            if (! isTls13Supported()) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            }

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    public void testTwoWay() throws Exception {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "TLS" };
        for (String protocol : protocols) {
            performTestTwoWay("openssl." + protocol, "openssl." + protocol, protocol);
        }
    }

    @Test
    public void testTwoWayTLS13() throws Exception {
        Assume.assumeTrue(isTls13Supported());
        performTestTwoWay("openssl.TLSv1.3", "openssl.TLSv1.3", "TLSv1.3");
    }

    @Test
    public void testTwoWayInterop() throws Exception {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String protocol : protocols) {
            performTestTwoWay("openssl." + protocol, protocol, protocol); // openssl server
        }
        for (String protocol : protocols) {
            performTestTwoWay(protocol, "openssl." + protocol, protocol); // openssl client
        }
    }

    @Test
    public void testTwoWayInteropTLS13() throws Exception {
        Assume.assumeTrue(isTls13Supported());
        performTestTwoWay("openssl.TLSv1.3", "TLSv1.3", "TLSv1.3"); // openssl server
        performTestTwoWay("TLSv1.3", "openssl.TLSv1.3", "TLSv1.3"); // openssl client
    }

    private void performTestTwoWay(String serverProvider, String clientProvider, String protocol) throws Exception {
        final SSLContext serverContext = SSLTestUtils.createSSLContext(serverProvider);
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<SSLSocket> socketFuture = executorService.submit(() -> {
            try {
                SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
                SSLSocket sslSocket = (SSLSocket) clientContext.getSocketFactory().createSocket(HOST, PORT);
                sslSocket.setReuseAddress(true);
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
            String expectedProtocol;
            if (protocol.equals("TLS")) {
                expectedProtocol = isTls13Supported() ? "TLSv1.3" : "TLSv1.2";
            } else {
                expectedProtocol = protocol;
            }
            Assert.assertEquals(expectedProtocol, clientSession.getProtocol());
            Assert.assertEquals(expectedProtocol, serverSession.getProtocol());
            Assert.assertEquals(expectedProtocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(clientSession.getCipherSuite()));
            Assert.assertEquals(expectedProtocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(serverSession.getCipherSuite()));
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
