package com.youzh.lingtu.sign.crypto.utils;

import org.spongycastle.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
