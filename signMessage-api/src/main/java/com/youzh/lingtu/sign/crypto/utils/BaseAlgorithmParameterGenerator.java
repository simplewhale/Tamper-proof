package com.youzh.lingtu.sign.crypto.utils;

import java.security.*;

public abstract class BaseAlgorithmParameterGenerator
    extends AlgorithmParameterGeneratorSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    protected SecureRandom  random;
    protected int           strength = 1024;

    public BaseAlgorithmParameterGenerator()
    {
    }

    protected final AlgorithmParameters createParametersInstance(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return helper.createAlgorithmParameters(algorithm);
    }

    protected void engineInit(
        int             strength,
        SecureRandom    random)
    {
        this.strength = strength;
        this.random = random;
    }
}
