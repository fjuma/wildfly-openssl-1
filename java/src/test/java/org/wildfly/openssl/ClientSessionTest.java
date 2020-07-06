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

import org.junit.Test;

/**
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
public class ClientSessionTest extends ClientSessionTestBase {

    @Test
    public void testOpenSsl() throws Exception {
        final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2"}; // testing session id doesn't make sense for TLSv1.3 or higher
        for (String provider : providers) {
            testSessionId(SSLTestUtils.createSSLContext(provider), provider);
        }
    }

    @Test
    public void testSessionTimeoutOpenSsl() throws Exception {
        testSessionTimeout("openssl.TLSv1", "openssl.TLSv1");
    }

    @Test
    public void testSessionTimeoutOpenSslTLS13() throws Exception {
        testSessionTimeoutTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionInvalidationOpenSsl() throws Exception {
        final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2" };
        for (String provider : providers) {
            testSessionInvalidation(provider, provider);
        }
        testSessionInvalidationTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testSessionSizeOpenSsl() throws Exception {
        final String[] providers = new String[] { "openssl.TLSv1", "openssl.TLSv1.1", "openssl.TLSv1.2"};
        for (String provider : providers) {
            testSessionSize(provider, provider);
        }
        testSessionSizeTLS13("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    public void testClientSessionInvalidationMultiThreadAccessOpenSsl() throws Exception {
        final String[] providers = new String[] { "openssl.TLSv1.2", "openssl.TLSv1.3" };
        for (String provider : providers) {
            testClientSessionInvalidationMultiThreadAccess(provider, provider);
        }
    }

}
