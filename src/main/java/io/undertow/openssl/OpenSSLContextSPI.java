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
package io.undertow.openssl;


import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.StringTokenizer;

import static io.undertow.openssl.OpenSSLLogger.ROOT_LOGGER;

public class OpenSSLContextSPI extends SSLContextSpi {
    private static final String BEGIN_CERT = "-----BEGIN RSA PRIVATE KEY-----\n";

    private static final String END_CERT = "\n-----END RSA PRIVATE KEY-----";

    private static final String[] ALGORITHMS = {"RSA"};

    private static final String defaultProtocol = "TLS";

    private final SSLHostConfig sslHostConfig;
    private OpenSSLServerSessionContext sessionContext;

    private List<String> ciphers = new ArrayList<>();

    public List<String> getCiphers() {
        return ciphers;
    }

    private String enabledProtocol;

    public String getEnabledProtocol() {
        return enabledProtocol;
    }

    public void setEnabledProtocol(String protocol) {
        enabledProtocol = (protocol == null) ? defaultProtocol : protocol;
    }

    protected final long ctx;

    static final CertificateFactory X509_CERT_FACTORY;
    private boolean initialized = false;

    static {
        try {
            X509_CERT_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    OpenSSLContextSPI(SSLHostConfig sslHostConfig)
            throws SSLException {
        this.sslHostConfig = sslHostConfig;
        boolean success = false;
        try {

            // SSL protocol
            int value = SSL.SSL_PROTOCOL_NONE;
            if (sslHostConfig.getProtocols().size() == 0) {
                value = SSL.SSL_PROTOCOL_ALL;
            } else {
                for (String protocol : sslHostConfig.getProtocols()) {
                    if (SSL.SSL_PROTO_SSLv2Hello.equalsIgnoreCase(protocol)) {
                        // NO-OP. OpenSSL always supports SSLv2Hello
                    } else if (SSL.SSL_PROTO_SSLv2.equalsIgnoreCase(protocol)) {
                        value |= SSL.SSL_PROTOCOL_SSLV2;
                    } else if (SSL.SSL_PROTO_SSLv3.equalsIgnoreCase(protocol)) {
                        value |= SSL.SSL_PROTOCOL_SSLV3;
                    } else if (SSL.SSL_PROTO_TLSv1.equalsIgnoreCase(protocol)) {
                        value |= SSL.SSL_PROTOCOL_TLSV1;
                    } else if (SSL.SSL_PROTO_TLSv1_1.equalsIgnoreCase(protocol)) {
                        value |= SSL.SSL_PROTOCOL_TLSV1_1;
                    } else if (SSL.SSL_PROTO_TLSv1_2.equalsIgnoreCase(protocol)) {
                        value |= SSL.SSL_PROTOCOL_TLSV1_2;
                    } else if (SSL.SSL_PROTO_ALL.equalsIgnoreCase(protocol)) {
                        value |= SSL.SSL_PROTOCOL_ALL;
                    } else {
                        // Protocol not recognized, fail to start as it is safer than
                        // continuing with the default which might enable more than the
                        // is required
                        throw ROOT_LOGGER.invalidSSLProtocol(protocol);
                    }
                }
            }

            // Create SSL Context
            try {
                ctx = SSL.makeSSLContext(value, SSL.SSL_MODE_SERVER);
            } catch (Exception e) {
                // If the sslEngine is disabled on the AprLifecycleListener
                // there will be an Exception here but there is no way to check
                // the AprLifecycleListener settings from here
                throw ROOT_LOGGER.failedToMakeSSLContext(e);
            }
            success = true;
        } catch (Exception e) {
            throw ROOT_LOGGER.failedToInitialiseSSLContext(e);
        }
    }

    /**
     * Setup the SSL_CTX
     *
     * @param kms Must contain a KeyManager of the type
     *            {@code OpenSSLKeyManager}
     * @param tms
     */
    private synchronized void init(KeyManager[] kms, TrustManager[] tms) {
        if (initialized) {
            ROOT_LOGGER.initCalledMultipleTimes();
            return;
        }
        try {
            boolean legacyRenegSupported = false;
            try {
                legacyRenegSupported = SSL.hasOp(SSL.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
                if (legacyRenegSupported)
                    if (sslHostConfig.getInsecureRenegotiation()) {
                        SSL.setSSLContextOptions(ctx, SSL.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
                    } else {
                        SSL.clearSSLContextOptions(ctx, SSL.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
                    }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!legacyRenegSupported) {
                // OpenSSL does not support unsafe legacy renegotiation.
                ROOT_LOGGER.debug("Your version of OpenSSL does not support legacy renegotiation");
            }
            // Use server's preference order for ciphers (rather than
            // client's)
            boolean orderCiphersSupported = false;
            try {
                orderCiphersSupported = SSL.hasOp(SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
                if (orderCiphersSupported) {
                    if (sslHostConfig.getHonorCipherOrder()) {
                        SSL.setSSLContextOptions(ctx, SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
                    } else {
                        SSL.clearSSLContextOptions(ctx, SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
                    }
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!orderCiphersSupported) {
                // OpenSSL does not support ciphers ordering.
                ROOT_LOGGER.noHonorCipherOrder();
            }

            // Disable compression if requested
            boolean disableCompressionSupported = false;
            try {
                disableCompressionSupported = SSL.hasOp(SSL.SSL_OP_NO_COMPRESSION);
                if (disableCompressionSupported) {
                    if (sslHostConfig.getDisableCompression()) {
                        SSL.setSSLContextOptions(ctx, SSL.SSL_OP_NO_COMPRESSION);
                    } else {
                        SSL.clearSSLContextOptions(ctx, SSL.SSL_OP_NO_COMPRESSION);
                    }
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!disableCompressionSupported) {
                ROOT_LOGGER.noDisableCompression();
            }

            // Disable TLS Session Tickets (RFC4507) to protect perfect forward secrecy
            boolean disableSessionTicketsSupported = false;
            try {
                disableSessionTicketsSupported = SSL.hasOp(SSL.SSL_OP_NO_TICKET);
                if (disableSessionTicketsSupported) {
                    if (sslHostConfig.getDisableSessionTickets()) {
                        SSL.setSSLContextOptions(ctx, SSL.SSL_OP_NO_TICKET);
                    } else {
                        SSL.clearSSLContextOptions(ctx, SSL.SSL_OP_NO_TICKET);
                    }
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!disableSessionTicketsSupported) {
                // OpenSSL is too old to support TLS Session Tickets.
                ROOT_LOGGER.noDisableSessionTickets();
            }

            // Set session cache size, if specified
            if (sslHostConfig.getSessionCacheSize() > 0) {
                SSL.setSessionCacheSize(ctx, sslHostConfig.getSessionCacheSize());
            } else {
                // Get the default session cache size using SSLContext.setSessionCacheSize()
                long sessionCacheSize = SSL.setSessionCacheSize(ctx, 20480);
                // Revert the session cache size to the default value.
                SSL.setSessionCacheSize(ctx, sessionCacheSize);
            }

            // Set session timeout, if specified
            if (sslHostConfig.getSessionTimeout() > 0) {
                SSL.setSessionCacheTimeout(ctx, sslHostConfig.getSessionTimeout());
            } else {
                // Get the default session timeout using SSLContext.setSessionCacheTimeout()
                long sessionTimeout = SSL.setSessionCacheTimeout(ctx, 300);
                // Revert the session timeout to the default value.
                SSL.setSessionCacheTimeout(ctx, sessionTimeout);
            }

            // List the ciphers that the client is permitted to negotiate
            String ciphers = sslHostConfig.getCiphers();
            if (!("ALL".equals(ciphers)) && ciphers.indexOf(":") == -1) {
                StringTokenizer tok = new StringTokenizer(ciphers, ",");
                this.ciphers = new ArrayList<>();
                while (tok.hasMoreTokens()) {
                    String token = tok.nextToken().trim();
                    if (!"".equals(token)) {
                        this.ciphers.add(token);
                    }
                }
                ciphers = CipherSuiteConverter.toOpenSsl(ciphers);
            } else {
                this.ciphers = OpenSSLCipherConfigurationParser.parseExpression(ciphers);
            }
            SSL.setCipherSuite(ctx, ciphers);
            // Load Server key and certificate
            X509KeyManager keyManager = chooseKeyManager(kms);
            if (keyManager == null) {
                throw OpenSSLLogger.ROOT_LOGGER.couldNotFindSuitableKeyManger();
            }
            boolean oneFound = false;
            for (String algorithm : ALGORITHMS) {

                final String[] aliases = keyManager.getServerAliases(algorithm, null);
                if (aliases != null && aliases.length != 0) {
                    oneFound = true;
                    String alias = aliases[0];
                    ROOT_LOGGER.debugf("Using alias %s", alias);

                    X509Certificate certificate = keyManager.getCertificateChain(alias)[0];
                    PrivateKey key = keyManager.getPrivateKey(alias);
                    StringBuilder sb = new StringBuilder(BEGIN_CERT);
                    sb.append(Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded()));
                    sb.append(END_CERT);
                    SSL.setCertificate(ctx, certificate.getEncoded(), sb.toString().getBytes(StandardCharsets.US_ASCII), algorithm.equals("RSA") ? SSL.SSL_AIDX_RSA : SSL.SSL_AIDX_DSA);
                }
            }

            if (!oneFound) {
                throw ROOT_LOGGER.couldNotExtractAliasFromKeyManager();
            }
            /*
            // Support Client Certificates
            SSL.setCACertificate(ctx,
                    SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificateFile()),
                    SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificatePath()));
            // Set revocation
            SSL.setCARevocation(ctx,
                    SSLHostConfig.adjustRelativePath(
                            sslHostConfig.getCertificateRevocationListFile()),
                    SSLHostConfig.adjustRelativePath(
                            sslHostConfig.getCertificateRevocationListPath()));
            */
            // Client certificate verification
            int value = 0;
            switch (sslHostConfig.getCertificateVerification()) {
                case NONE:
                    value = SSL.SSL_CVERIFY_NONE;
                    break;
                case OPTIONAL:
                    value = SSL.SSL_CVERIFY_OPTIONAL;
                    break;
                case OPTIONAL_NO_CA:
                    value = SSL.SSL_CVERIFY_OPTIONAL_NO_CA;
                    break;
                case REQUIRED:
                    value = SSL.SSL_CVERIFY_REQUIRE;
                    break;
            }
            SSL.setSSLContextVerify(ctx, value, sslHostConfig.getCertificateVerificationDepth());

            if (tms != null) {
                final X509TrustManager manager = chooseTrustManager(tms);
                SSL.setCertVerifyCallback(ctx, new CertificateVerifier() {
                    @Override
                    public boolean verify(long ssl, byte[][] chain, String auth) {
                        X509Certificate[] peerCerts = certificates(chain);
                        try {
                            manager.checkClientTrusted(peerCerts, auth);
                            return true;
                        } catch (Exception e) {
                            ROOT_LOGGER.debug("Certificate verification failed", e);
                        }
                        return false;
                    }
                });
            }
            String[] protos = new OpenSSLProtocols(enabledProtocol).getProtocols();

            sessionContext = new OpenSSLServerSessionContext(ctx);
            sessionContext.setSessionIdContext("test".getBytes(StandardCharsets.US_ASCII));
            initialized = true;

            //TODO: ALPN must be optional
            SSL.enableAlpn(ctx);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private X509KeyManager chooseKeyManager(KeyManager[] tms) {
        for (KeyManager tm : tms) {
            if (tm instanceof X509KeyManager) {
                return (X509KeyManager) tm;
            }
        }
        throw ROOT_LOGGER.keyManagerMissing();
    }

    static X509TrustManager chooseTrustManager(TrustManager[] managers) {
        for (TrustManager m : managers) {
            if (m instanceof X509TrustManager) {
                return (X509TrustManager) m;
            }
        }
        throw ROOT_LOGGER.trustManagerMissing();
    }

    private static X509Certificate[] certificates(byte[][] chain) {
        X509Certificate[] peerCerts = new X509Certificate[chain.length];
        for (int i = 0; i < peerCerts.length; i++) {
            peerCerts[i] = new OpenSslX509Certificate(chain[i]);
        }
        return peerCerts;
    }

    public SSLSessionContext getServerSessionContext() {
        return sessionContext;
    }

    public SSLEngine createSSLEngine() {
        return new OpenSSLEngine(ctx, defaultProtocol, false, sessionContext);
    }

    public SSLServerSocketFactory getServerSocketFactory() {
        throw new UnsupportedOperationException();
    }

    public SSLParameters getSupportedSSLParameters() {
        throw new UnsupportedOperationException();
    }

    /**
     * Generates a key specification for an (encrypted) private key.
     *
     * @param password characters, if {@code null} or empty an unencrypted key
     *                 is assumed
     * @param key      bytes of the DER encoded private key
     * @return a key specification
     * @throws IOException                        if parsing {@code key} fails
     * @throws NoSuchAlgorithmException           if the algorithm used to encrypt
     *                                            {@code key} is unknown
     * @throws NoSuchPaddingException             if the padding scheme specified in the
     *                                            decryption algorithm is unknown
     * @throws InvalidKeySpecException            if the decryption key based on
     *                                            {@code password} cannot be generated
     * @throws InvalidKeyException                if the decryption key based on
     *                                            {@code password} cannot be used to decrypt {@code key}
     * @throws InvalidAlgorithmParameterException if decryption algorithm
     *                                            parameters are somehow faulty
     */
    protected static PKCS8EncodedKeySpec generateKeySpec(char[] password, byte[] key)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        if (password == null || password.length == 0) {
            return new PKCS8EncodedKeySpec(key);
        }

        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, encryptedPrivateKeyInfo.getAlgParameters());

        return encryptedPrivateKeyInfo.getKeySpec(cipher);
    }

    @Override
    protected final void finalize() throws Throwable {
        super.finalize();
        synchronized (OpenSSLContextSPI.class) {
            if (ctx != 0) {
                SSL.freeSSLContext(ctx);
            }
        }
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        init(km, tm);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        throw ROOT_LOGGER.unsupportedMethod();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw ROOT_LOGGER.unsupportedMethod();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return createSSLEngine();
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return sessionContext;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return sessionContext;
    }

    public void sessionRemoved(byte[] session) {
        sessionContext.remove(session);
    }
}
