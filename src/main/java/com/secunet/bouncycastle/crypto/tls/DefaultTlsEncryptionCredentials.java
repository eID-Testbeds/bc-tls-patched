package com.secunet.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import com.secunet.bouncycastle.crypto.tls.AbstractTlsEncryptionCredentials;
import com.secunet.bouncycastle.crypto.tls.Certificate;
import com.secunet.bouncycastle.crypto.tls.TlsContext;
import com.secunet.bouncycastle.crypto.tls.TlsRSAUtils;

public class DefaultTlsEncryptionCredentials extends AbstractTlsEncryptionCredentials
{
    protected TlsContext context;
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;

    public DefaultTlsEncryptionCredentials(TlsContext context, Certificate certificate,
        AsymmetricKeyParameter privateKey)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        if (privateKey instanceof RSAKeyParameters)
        {
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }

        this.context = context;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret)
        throws IOException
    {
        return TlsRSAUtils.safeDecryptPreMasterSecret(context, (RSAKeyParameters)privateKey, encryptedPreMasterSecret);
    }
}
