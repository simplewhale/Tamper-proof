package com.youzh.lingtu.genkey;

import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;

import java.security.SecureRandom;


/**
 * @author alen
 */
public class GenerateMnemonic {

    /**
     * BIP39生成助记词
     * 配置：12个英文单词，默认用空格隔开
     * @return
     */
    public static String genMnemonic() {

        StringBuilder sb = new StringBuilder();
        byte[] entropy = new byte[Words.TWELVE.byteLength()];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE).createMnemonic(entropy, sb::append);
        String mnemonic = sb.toString();

        return mnemonic;
    }


}

