package com.youzh.lingtu.sign.crypto.utils;


/**
 * generic interface for an Elliptic Curve Key.
 */
public interface ECKey
{
    /**
     * return a parameter specification representing the EC domain parameters
     * for the key.
     */
    public com.youzh.lingtu.sign.crypto.utils.ECParameterSpec getParameters();
}
