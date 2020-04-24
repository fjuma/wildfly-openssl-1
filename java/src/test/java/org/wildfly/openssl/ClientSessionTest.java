/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

package org.wildfly.openssl;

import static org.wildfly.openssl.SSLTestUtils.HOST;
import static org.wildfly.openssl.SSLTestUtils.PORT;

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
public class ClientSessionTest extends AbstractOpenSSLTest {

    private static final byte[] HELLO_WORLD = "hello world".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void testJsse() throws Exception {
        final String[] providers = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" }; // testing session id doesn't make sense for TLSv1.3 or higher
        for (String provider : providers) {
            testSessionId(SSLTestUtils.createSSLContext(provider), "openssl." + provider);
        }
    }

    @Test
    public void testOpenSsl() throws Exception {
        final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2"}; // testing session id doesn't make sense for TLSv1.3 or higher
        for (String provider : providers) {
            testSessionId(SSLTestUtils.createSSLContext(provider), provider);
        }
    }

    @Test
    public void testSessionTimeoutJsse() throws Exception {
        final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String protocol : protocols) {
            testSessionTimeout(protocol, "openssl." + protocol);
        }
        testSessionTimeoutTLS13("TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionTimeoutOpenSsl() throws Exception {
        /*final String[] protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String protocol : protocols) {
            testSessionTimeout("openssl." + protocol, "openssl." + protocol);
        }*/
        testSessionTimeoutTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    private void testSessionTimeout(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        try (
                ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port1);
                ServerSocket serverSocket2 = SSLTestUtils.createServerSocket(port2)
        ) {

            final Thread acceptThread1 = startServer(serverSocket1, serverProvider);
            final Thread acceptThread2 = startServer(serverSocket2, serverProvider);

            SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
            final SSLSessionContext clientSession = clientContext.getClientSessionContext();
            byte[] host1SessionId = connectAndWrite(clientContext, port1);
            byte[] host2SessionId = connectAndWrite(clientContext, port2);

            // No timeout was set, id's should be identical
            Assert.assertArrayEquals(host1SessionId, connectAndWrite(clientContext, port1));
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));

            // Set the session timeout to 1 second and sleep for 2 to ensure the timeout works
            clientSession.setSessionTimeout(1);
            TimeUnit.SECONDS.sleep(2L);
            Assert.assertFalse(Arrays.equals(host1SessionId, connectAndWrite(clientContext, port1)));
            Assert.assertFalse(Arrays.equals(host1SessionId, connectAndWrite(clientContext, port2)));

            serverSocket1.close();
            serverSocket2.close();
            acceptThread1.join();
            acceptThread2.join();
        }
    }

    private void testSessionTimeoutTLS13(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;
        Server server1 = startServerTLS13(serverProvider, port1);
        Server server2 = startServerTLS13(serverProvider, port2);
        server1.signal();
        server2.signal();
        SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
        SSLSessionContext clientSession = clientContext.getClientSessionContext();
        while (! server1.started) {
            Thread.yield();
        }
        while (! server2.started) {
            Thread.yield();
        }
        SSLSession firstSession1 = connect(clientContext, port1, null);
        SSLSession firstSession2 = connect(clientContext, port2, null);
        System.out.println("ONE " + firstSession1.getCreationTime());
        System.out.println("TWO " + firstSession2.getCreationTime());
        server1.signal();
        server2.signal();
        Thread.sleep(10);
        SSLSession secondSession1 = connect(clientContext, port1, null);
        SSLSession secondSession2 = connect(clientContext, port2, null);
        System.out.println("ONE AGAIN SHOULD BE SAME " + secondSession1.getCreationTime());
        System.out.println("TWO AGAIN SHOULD BE SAME " + secondSession2.getCreationTime());
        server1.signal();
        server2.signal();
        // No timeout was set, creation times should be identical
        Assert.assertEquals(firstSession1.getCreationTime(), secondSession1.getCreationTime());
        Assert.assertEquals(firstSession2.getCreationTime(), secondSession2.getCreationTime());
        // Set the session timeout to 1 second and sleep for 2 to ensure the timeout works
        clientSession.setSessionTimeout(1);
        TimeUnit.SECONDS.sleep(2L);
        SSLSession thirdSession1 = connect(clientContext, port1, null);
        SSLSession thirdSession2 = connect(clientContext, port2, null);
        System.out.println("ONE SHOULD BE DIFF " + thirdSession1.getCreationTime());
        System.out.println("TWO " + thirdSession2.getCreationTime());
        server1.go = false;
        server1.signal();
        server2.go = false;
        server2.signal();
        Assert.assertTrue(secondSession1.getCreationTime() != thirdSession1.getCreationTime());
        Assert.assertTrue(secondSession2.getCreationTime() != thirdSession2.getCreationTime());
    }

    @Test
    public void testSessionInvalidationJsse() throws Exception {
        /*final String[] providers = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String provider : providers) {
            testSessionInvalidation(provider, "openssl." + provider);
        }*/
        testSessionInvalidationTLS13("TLSv1.3", "openssl.TLSv1.3");
    }

    //@Test
    public void testSessionInvalidationOpenSsl() throws Exception {
        /*final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2" };
        for (String provider : providers) {
            testSessionInvalidation(provider, provider);
        }*/
        testSessionInvalidationTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    private void testSessionInvalidation(String serverProvider, String clientProvider) throws Exception {
        final int port = PORT;

        try (ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port)) {

            final Thread acceptThread1 = startServer(serverSocket1, serverProvider);
            final FutureSessionId future = new FutureSessionId();
            SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
                socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListener(future));
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getSession().invalidate();
                socket.getOutputStream().flush();
            }
            byte[] invalided = future.get();
            Assert.assertNotNull(invalided);
            byte[] newSession = connectAndWrite(clientContext, port);
            Assert.assertNotNull(newSession);

            Assert.assertFalse(Arrays.equals(invalided, newSession));

            serverSocket1.close();
            acceptThread1.join();
        }
    }

    private void testSessionInvalidationTLS13(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;

        Server server = startServerTLS13(serverProvider, port1);
        server.signal();
        SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
        SSLSessionContext clientSession = clientContext.getClientSessionContext();
        while (! server.started) {
            Thread.yield();
        }
        clientSession.setSessionCacheSize(0); //////////////////////////////////////////
        FutureSessionCreationTime f1 = new FutureSessionCreationTime();
        SSLSession firstSession = connect(clientContext, port1, f1);
        long blah1 = f1.get();
        server.signal();
        Assert.assertTrue(firstSession.isValid());
        firstSession.invalidate();
        ///////////////////////clientSession.setSessionTimeout(0);
        Assert.assertFalse(firstSession.isValid());
        FutureSessionCreationTime f2 = new FutureSessionCreationTime();
        long newTime = System.currentTimeMillis();
        ///////////////////////////Thread.sleep(500);
        ///////////clientSession.setSessionTimeout(1);
        //////////TimeUnit.SECONDS.sleep(2L);
        SSLSession secondSession = connect(clientContext, port1, f2);
        long blah2 = f2.get();
        server.go = false;
        server.signal();
        System.out.println("ONE " + firstSession.getCreationTime() + blah1 + "obj " + firstSession);
        System.out.println("NOW " + newTime);
        System.out.println("TWO " + secondSession.getCreationTime() + blah2 + "obj " + secondSession);
        Assert.assertTrue(secondSession.isValid());
        //Assert.assertTrue(blah1 != blah2);
        Assert.assertTrue(firstSession.getCreationTime() != secondSession.getCreationTime());
    }

    @Test
    public void testSessionSizeJsse() throws Exception {
        final String[] providers = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        /*for (String provider : providers) {
            testSessionSize(provider, "openssl." + provider);
        }*/
        //testSessionSize("TLSv1.2", "openssl.TLSv1.2");
        testSessionSizeTLS13("TLSv1.3", "TLSv1.3");
    }

    @Test
    public void testSessionSizeOpenSsl() throws Exception {
        /*final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2"};
        for (String provider : providers) {
            testSessionSize(provider, provider);
        }*/
        testSessionSizeTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }


    private void testSessionSize(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        try (
                ServerSocket serverSocket1 = SSLTestUtils.createServerSocket(port1);
                ServerSocket serverSocket2 = SSLTestUtils.createServerSocket(port2)
        ) {

            final Thread acceptThread1 = startServer(serverSocket1, serverProvider);
            final Thread acceptThread2 = startServer(serverSocket2, serverProvider);
            SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);

            final SSLSessionContext clientSession = clientContext.getClientSessionContext();

            byte[] host1SessionId = connectAndWrite(clientContext, port1);
            byte[] host2SessionId = connectAndWrite(clientContext, port2);

            // No cache limit was set, id's should be identical
            Assert.assertArrayEquals(host1SessionId, connectAndWrite(clientContext, port1));
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));

            // Set the cache size to 1
            clientSession.setSessionCacheSize(1);
            // The second session id should be the one kept as it was the last one used
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));
            // Connect again to the first host, this should not match the initial session id for the first host
            byte[] nextId = connectAndWrite(clientContext, port1);
            Assert.assertFalse(Arrays.equals(host1SessionId, nextId));
            // Once more connect to the first host and this should match the previous session id
            Assert.assertArrayEquals(nextId, connectAndWrite(clientContext, port1));
            // Connect to the second host which should be purged at this point
            Assert.assertFalse(Arrays.equals(nextId, connectAndWrite(clientContext, port2)));

            // Reset the cache limit and ensure both sessions are cached
            clientSession.setSessionCacheSize(0);
            host1SessionId = connectAndWrite(clientContext, port1);
            host2SessionId = connectAndWrite(clientContext, port2);

            // No cache limit was set, id's should be identical
            Assert.assertArrayEquals(host1SessionId, connectAndWrite(clientContext, port1));
            Assert.assertArrayEquals(host2SessionId, connectAndWrite(clientContext, port2));

            serverSocket1.close();
            serverSocket2.close();
            acceptThread1.join();
            acceptThread2.join();
        }
    }

    private void testSessionSizeTLS13(String serverProvider, String clientProvider) throws Exception {
        final int port1 = PORT;
        final int port2 = SSLTestUtils.SECONDARY_PORT;

        Server server1 = startServerTLS13(serverProvider, port1);
        Server server2 = startServerTLS13(serverProvider, port2);
        server1.signal();
        server2.signal();

        SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
        final SSLSessionContext clientSession = clientContext.getClientSessionContext();

        while (! server1.started) {
            Thread.yield();
        }
        while (! server2.started) {
            Thread.yield();
        }

        SSLSession host1Session = connect(clientContext, port1, null);
        SSLSession host2Session = connect(clientContext, port2, null);
        server1.signal();
        server2.signal();

        // No cache limit was set, id's should be identical
        Assert.assertEquals(host1Session.getCreationTime(), connect(clientContext, port1, null).getCreationTime());
        Assert.assertEquals(host2Session.getCreationTime(), connect(clientContext, port2, null).getCreationTime());
        /*System.out.println("ONE " + host1Session.getCreationTime());
        System.out.println("TWO " + host2Session.getCreationTime());*/
        server1.signal();
        server2.signal();

        // Set the cache size to 1
        clientSession.setSessionCacheSize(1);
        // The second session should be the one kept as it was the last one used
        Assert.assertEquals(host2Session.getCreationTime(), connect(clientContext, port2, null).getCreationTime());
        // Connect again to the first host, this should not match the initial session for the first host
        SSLSession nextSession = connect(clientContext, port1, null);
        server1.signal();
        server2.signal();

        System.out.println("ONE AGAIN " + nextSession.getCreationTime());
        Assert.assertFalse(host1Session.getCreationTime() == nextSession.getCreationTime());
        // Once more connect to the first host and this should match the previous session
        /*Assert.assertEquals(nextSession.getCreationTime(), connect(clientContext, port1, null).getCreationTime());
        // Connect to the second host which should be purged at this point
        Assert.assertFalse(nextSession.getCreationTime() == connect(clientContext, port2, null).getCreationTime());
        server1.signal();
        server2.signal();

        // Reset the cache limit and ensure both sessions are cached
        clientSession.setSessionCacheSize(0);
        host1Session = connect(clientContext, port1, null);
        host2Session = connect(clientContext, port2, null);
        server1.signal();
        server2.signal();

        // No cache limit was set, id's should be identical
        Assert.assertEquals(host1Session.getCreationTime(), connect(clientContext, port1, null).getCreationTime());
        Assert.assertEquals(host2Session.getCreationTime(), connect(clientContext, port2, null).getCreationTime());
        server1.go = false;
        server1.signal();
        server2.go = false;
        server2.signal();*/
    }

    /**
     * Tests that invalidation of a client session, for whatever reason, when multiple threads
     * are involved in interacting with the server through a SSL socket, doesn't lead to a JVM crash
     *
     * @throws Exception
     */
    //@Test
    public void testClientSessionInvalidationMultiThreadAccessJsse() throws Exception {
        final String[] providers = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        for (String provider : providers) {
            testClientSessionInvalidationMultiThreadAccess(provider, "openssl." + provider);
        }
    }

    //@Test
    public void testClientSessionInvalidationMultiThreadAccessOpenSsl() throws Exception {
        final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2"};
        for (String provider : providers) {
            testClientSessionInvalidationMultiThreadAccess(provider, provider);
        }
    }

    private void testClientSessionInvalidationMultiThreadAccess(String serverProvider, String clientProvider) throws Exception {
        final int port = PORT;
        final int numThreads = 10;
        final ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket(port)) {
            final Thread acceptThread = startServer(serverSocket, serverProvider);
            final SSLContext clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
            final List<Future<Void>> taskResults = new ArrayList<>();
            for (int i = 0; i < numThreads; i++) {
                taskResults.add(executor.submit(new SocketWriter(clientContext, SSLTestUtils.HOST, port)));
            }
            // wait for results
            for (int i = 0; i < numThreads; i++) {
                taskResults.get(i).get(10, TimeUnit.SECONDS);
            }
            serverSocket.close();
            acceptThread.join();
        } finally {
            executor.shutdownNow();
        }
    }

    private void testSessionId(final SSLContext sslContext, final String provider) throws IOException, InterruptedException {
        final int iterations = 10;
        final Collection<SSLSocket> toClose = new ArrayList<>();

        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {

            EchoRunnable echo = new EchoRunnable(serverSocket, sslContext, new AtomicReference<>(), (engine -> {
                try {
                    engine.setEnabledProtocols(new String[]{ "TLSv1", "TLSv1.1", "TLSv1.2"});
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            final Thread acceptThread = new Thread(echo);
            acceptThread.start();

            byte[] sessionID;
            // Create a connection to get a session ID, all other session id's should match
            SSLContext clientContext = SSLTestUtils.createClientSSLContext(provider);
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.startHandshake();
                final byte[] id = socket.getSession().getId();
                sessionID = Arrays.copyOf(id, id.length);
            }

            final CountDownLatch latch = new CountDownLatch(iterations);

            for (int i = 0; i < iterations; i++) {
                final SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket();
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.addHandshakeCompletedListener(new AssertingHandshakeCompletedListener(latch, sessionID, getExpectedProtocolFromProvider(provider)));
                socket.startHandshake();
                toClose.add(socket);
            }
            if (!latch.await(30, TimeUnit.SECONDS)) {
                Assert.fail("Failed to complete handshakes");
            }
            serverSocket.close();
            acceptThread.join(1000);
        } finally {
            for (SSLSocket socket : toClose) {
                try {
                    socket.close();
                } catch (Exception ignore) {
                }
            }
        }

    }

    /*@Test // FJ CAN REMOVE THIS
    public void testTwoWay() throws Exception {
       *//* final SSLContext serverContext = SSLTestUtils.createSSLContext("TLSv1.3");
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<SSLSession> sessionFuture1 = executorService.submit(() -> {
            try {
                SSLContext clientContext = SSLTestUtils.createClientSSLContext("TLSv1.3");
                SSLSocket sslSocket = (SSLSocket) clientContext.getSocketFactory().createSocket(HOST, PORT);
                //sslSocket.getSession();
                sslSocket.getOutputStream().write(HELLO_WORLD);
                sslSocket.getOutputStream().flush();
                SSLSession result = sslSocket.getSession();
                sslSocket.close();
                return result;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Future<SSLSession> sessionFuture2 = executorService.submit(() -> {
            try {
                SSLContext clientContext = SSLTestUtils.createClientSSLContext("TLSv1.3");
                SSLSocket sslSocket = (SSLSocket) clientContext.getSocketFactory().createSocket(HOST, PORT);
                //sslSocket.getSession();
                sslSocket.getOutputStream().write(HELLO_WORLD);
                sslSocket.getOutputStream().flush();
                SSLSession result = sslSocket.getSession();
                sslSocket.close();
                return result;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        SSLServerSocket sslServerSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(PORT, 10, InetAddress.getByName(HOST));
        SSLSocket serverSocket = (SSLSocket) sslServerSocket.accept();
        SSLSession serverSession = serverSocket.getSession();
        //SSLSocket clientSocket = sessionFuture1.get();
        SSLSession clientSession1 = sessionFuture1.get();
        //SSLSocket clientSocket2 = sessionFuture2.get();
       //sslServerSocket.accept();
        SSLSession clientSession2 = sessionFuture2.get();

        try {
            //Assert.assertEquals("TLSv1.3", clientSession.getProtocol());
            //Assert.assertEquals("TLSv1.3", serverSession.getProtocol());
            //Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(clientSession.getCipherSuite()));
            //Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(serverSession.getCipherSuite()));

        } finally {
            //serverSocket.close();
            //clientSocket.close();
            //sslServerSocket.close();
        }*//*
        final Collection<SSLSocket> toClose = new ArrayList<>();
        try (ServerSocket serverSocket = SSLTestUtils.createServerSocket()) {

            EchoRunnable echo = new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext("TLSv1.3"), new AtomicReference<>(), (engine -> {
                try {
                    engine.setEnabledProtocols(new String[]{ "TLSv1.3" });
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
            final Thread acceptThread = new Thread(echo);
            acceptThread.start();

            byte[] sessionID;
            long creationTime1;
            // Create a connection to get a session ID, all other session id's should match
            SSLContext clientContext = SSLTestUtils.createClientSSLContext("TLSv1.3");
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getOutputStream().flush();
                //socket.connect(SSLTestUtils.createSocketAddress());
                //socket.startHandshake();
                //final byte[] id = socket.getSession().getId();
                //sessionID = Arrays.copyOf(id, id.length);
                creationTime1 = socket.getSession().getCreationTime();
            }

            int iterations = 1;
            final CountDownLatch latch = new CountDownLatch(iterations);

            for (int i = 0; i < iterations; i++) {
                final SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket();
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.addHandshakeCompletedListener(new AssertingHandshakeCompletedListener(latch, null, getExpectedProtocolFromProvider("TLSv1.3"), creationTime1));
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getOutputStream().flush();
                Assert.assertEquals(creationTime1, socket.getSession().getCreationTime());
                toClose.add(socket);
            }
            if (!latch.await(30, TimeUnit.SECONDS)) {
                Assert.fail("Failed to complete handshakes");
            }
            serverSocket.close();
            acceptThread.join(1000);
        } finally {
            for (SSLSocket socket : toClose) {
               try {
                    socket.close();
               } catch (Exception ignore) {
                }
            }
        }


    }
*/
    private byte[] connectAndWrite(final SSLContext context, final int port) throws IOException, ExecutionException, InterruptedException {
        final FutureSessionId future = new FutureSessionId();
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
            socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListener(future));
            socket.getOutputStream().write(HELLO_WORLD);
            socket.getOutputStream().flush();
        }
        return future.get();
    }

    private SSLSession connectAndWriteTLS13(final SSLContext context, final int port) throws IOException, ExecutionException, InterruptedException {
        //final FutureSessionCreationTime future = new FutureSessionCreationTime();
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
            //socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListenerTLS13(future));
            socket.getOutputStream().write(HELLO_WORLD);
            System.out.println("SESSION TIME " + socket.getSession().getCreationTime());
            socket.getOutputStream().flush();
            //SSLSession result = socket.getSession();
            //socket.close();
            return null;
        }
        //return future.get();
    }

    private static class AssertingHandshakeCompletedListener implements HandshakeCompletedListener {
        private final CountDownLatch latch;
        private final byte[] expectedSessionId;
        private final String expectedProtocol;

        private AssertingHandshakeCompletedListener(final CountDownLatch latch, final byte[] expectedSessionId, final String expectedProtocol) {
            this.latch = latch;
            this.expectedSessionId = expectedSessionId;
            this.expectedProtocol = expectedProtocol;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            latch.countDown();
            Assert.assertArrayEquals(expectedSessionId, event.getSession().getId());
            Assert.assertFalse(CipherSuiteConverter.isTLSv13CipherSuite(event.getCipherSuite()));
            Assert.assertEquals(expectedProtocol, event.getSession().getProtocol());
        }
    }

    private Thread startServer(final ServerSocket serverSocket, final String serverProvider) throws IOException {
        EchoRunnable echo = new EchoRunnable(serverSocket, SSLTestUtils.createSSLContext(serverProvider), new AtomicReference<>(), (engine -> {
            try {
                engine.setEnabledProtocols(new String[]{ "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" });
                return engine;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
        final Thread acceptThread = new Thread(echo);
        acceptThread.start();
        return acceptThread;
    }

    private static class FutureHandshakeCompletedListener implements HandshakeCompletedListener {
        private final FutureSessionId futureSessionId;

        private FutureHandshakeCompletedListener(final FutureSessionId futureSessionId) {
            this.futureSessionId = futureSessionId;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            futureSessionId.value = event.getSession().getId();
        }
    }

    private static class FutureSessionId implements Future<byte[]> {
        private final AtomicBoolean done = new AtomicBoolean(false);
        private volatile byte[] value;

        @Override
        public boolean cancel(final boolean mayInterruptIfRunning) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return done.get();
        }

        @Override
        public byte[] get() throws InterruptedException, ExecutionException {
            while (value == null) {
                TimeUnit.MILLISECONDS.sleep(10L);
            }
            done.set(true);
            return value;
        }

        @Override
        public byte[] get(final long timeout, final TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return get();
        }
    }

    private static class FutureHandshakeCompletedListenerTLS13 implements HandshakeCompletedListener {
        private final FutureSessionCreationTime futureSessionCreationTime;

        private FutureHandshakeCompletedListenerTLS13(final FutureSessionCreationTime futureSessionCreationTime) {
            this.futureSessionCreationTime = futureSessionCreationTime;
        }

        @Override
        public void handshakeCompleted(final HandshakeCompletedEvent event) {
            futureSessionCreationTime.value = event.getSession().getCreationTime();
        }
    }

    private static class FutureSessionCreationTime implements Future<Long> {
        private final AtomicBoolean done = new AtomicBoolean(false);
        private volatile Long value;

        @Override
        public boolean cancel(final boolean mayInterruptIfRunning) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return done.get();
        }

        @Override
        public Long get() throws InterruptedException, ExecutionException {
            while (value == null) {
                TimeUnit.MILLISECONDS.sleep(10L);
            }
            done.set(true);
            return value;
        }

        @Override
        public Long get(final long timeout, final TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return get();
        }
    }


    private class SocketWriter implements Callable<Void> {
        private final SSLContext sslClientContext;
        private final String host;
        private final int port;

        SocketWriter(final SSLContext sslClientContext, final String host, final int port) {
            this.sslClientContext = sslClientContext;
            this.host = host;
            this.port = port;
        }

        @Override
        public Void call() {
            // create a socket, connect, write some data, invalidate the session
            try (SSLSocket socket = (SSLSocket) this.sslClientContext.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(this.host, this.port));
                socket.getOutputStream().write(HELLO_WORLD);
                socket.getOutputStream().flush();
                socket.getSession().invalidate();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return null;
        }
    }

    private String getExpectedProtocolFromProvider(String provider) {
        if (provider.startsWith("openssl.")) {
            return provider.substring(provider.indexOf(".") + 1);
        } else {
            return provider;
        }
    }

    private static Server startServerTLS13(String provider, int port) {
        Server server = new Server(provider, port);
        new Thread(server).start();
        return server;
    }

    private static class Server implements Runnable {

        public volatile boolean go = true;
        private boolean signal = false;
        public volatile boolean started = false;
        private String provider;
        private int port;

        Server(String provider, int port) {
            this.provider = provider;
            this.port = port;
        }

        private synchronized void waitForSignal() {
            while (!signal) {
                try {
                    wait();
                } catch (InterruptedException ex) {
                    // do nothing
                }
            }
            signal = false;
        }
        public synchronized void signal() {
            signal = true;
            notify();
        }

        @Override
        public void run() {
            try {
                SSLContext serverContext = SSLTestUtils.createSSLContext(provider);
                SSLServerSocket sslServerSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(port, 10, InetAddress.getByName(HOST));

                waitForSignal();
                started = true;
                while (go) {
                    try {
                        System.out.println("Waiting for connection");
                        Socket sock = sslServerSocket.accept();
                        BufferedReader reader = new BufferedReader(
                                new InputStreamReader(sock.getInputStream()));
                        String line = reader.readLine();
                        System.out.println("server read: " + line);
                        PrintWriter out = new PrintWriter(
                                new OutputStreamWriter(sock.getOutputStream()));
                        out.println(line);
                        out.flush();
                        waitForSignal();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
                sslServerSocket.close();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    private static SSLSession connect(SSLContext sslContext, int port, boolean invalidate) {

        try {
            SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
            socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
            PrintWriter out = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream()));
            out.println("message");
            out.flush();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            String inMsg = reader.readLine();
            System.out.println("Client received: " + inMsg);
            SSLSession result = socket.getSession();
            if (invalidate) {
                socket.getSession().invalidate(); //////////////////
                socket.getOutputStream().flush(); /////////////
            }
            socket.close();
            return result;
        } catch (Exception ex) {
            // unexpected exception
            throw new RuntimeException(ex);
        }
    }

    private static SSLSession connect(SSLContext sslContext, int port, FutureSessionCreationTime future) {

        try {
            SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
            socket.connect(new InetSocketAddress(SSLTestUtils.HOST, port));
            if (future != null) {
                socket.addHandshakeCompletedListener(new FutureHandshakeCompletedListenerTLS13(future));
            }
            PrintWriter out = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream()));
            out.println("message");
            out.flush();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            String inMsg = reader.readLine();
            System.out.println("Client received: " + inMsg);
            SSLSession result = socket.getSession();
            socket.close();
            return result;
        } catch (Exception ex) {
            // unexpected exception
            throw new RuntimeException(ex);
        }
    }

}
