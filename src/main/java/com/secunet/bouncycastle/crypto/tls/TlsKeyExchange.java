package com.secunet.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.secunet.bouncycastle.crypto.tls.Certificate;
import com.secunet.bouncycastle.crypto.tls.CertificateRequest;
import com.secunet.bouncycastle.crypto.tls.TlsContext;
import com.secunet.bouncycastle.crypto.tls.TlsCredentials;

/**
 * A generic interface for key exchange implementations in (D)TLS.
 */
public interface TlsKeyExchange
{
    void init(TlsContext context);

    void skipServerCredentials()
        throws IOException;

    void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException;

    void processServerCertificate(Certificate serverCertificate)
        throws IOException;

    boolean requiresServerKeyExchange();

    byte[] generateServerKeyExchange()
        throws IOException;

    void skipServerKeyExchange()
        throws IOException;

    void processServerKeyExchange(InputStream input)
        throws IOException;

    void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException;

    void skipClientCredentials()
        throws IOException;

    void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException;

    void processClientCertificate(Certificate clientCertificate)
        throws IOException;

    void generateClientKeyExchange(OutputStream output)
        throws IOException;

    void processClientKeyExchange(InputStream input)
        throws IOException;

    byte[] generatePremasterSecret()
        throws IOException;
}
