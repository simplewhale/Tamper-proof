package com.youzh.lingtu.sign.crypto.utils;

import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricKeyInfoConverter
{
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException;
}
