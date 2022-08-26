package com.youzh.lingtu.sign.crypto.utils;

import javax.crypto.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Factory interface for instantiating JCA/JCE primitives.
 */
public interface JcaJceHelper
{
    Cipher createCipher(
            String algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException;

    Mac createMac(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyAgreement createKeyAgreement(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyGenerator createKeyGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyFactory createKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    SecretKeyFactory createSecretKeyFactory(String algorithm)
           throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    MessageDigest createDigest(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    Signature createSignature(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    CertificateFactory createCertificateFactory(String algorithm)
        throws NoSuchProviderException, CertificateException;
}
