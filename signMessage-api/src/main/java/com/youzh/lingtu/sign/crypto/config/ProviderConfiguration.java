package com.youzh.lingtu.sign.crypto.config;

import com.youzh.lingtu.sign.crypto.utils.ECParameterSpec;

import javax.crypto.spec.DHParameterSpec;

public interface ProviderConfiguration
{
    ECParameterSpec getEcImplicitlyCa();

    DHParameterSpec getDHDefaultParameters(int keySize);
}
