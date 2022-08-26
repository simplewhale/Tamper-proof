package com.youzh.lingtu.sign.crypto.digest;

import com.youzh.lingtu.sign.crypto.utils.BaseKeyGenerator;
import com.youzh.lingtu.sign.crypto.utils.BaseMac;
import com.youzh.lingtu.sign.crypto.utils.PBESecretKeyFactory;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.digests.GOST3411Digest;
import org.spongycastle.crypto.macs.HMac;
import com.youzh.lingtu.sign.crypto.config.ConfigurableProvider;


public class GOST3411
{
    private GOST3411()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new GOST3411Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new GOST3411Digest((GOST3411Digest)digest);

            return d;
        }
    }

    /**
     * GOST3411 HMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new GOST3411Digest()));
        }
    }

    /**
     * PBEWithHmacGOST3411
     */
    public static class PBEWithMacKeyFactory
        extends PBESecretKeyFactory
    {
        public PBEWithMacKeyFactory()
        {
            super("PBEwithHmacGOST3411", null, false, PKCS12, GOST3411, 256, 0);
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACGOST3411", 256, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = GOST3411.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.GOST3411", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST", "GOST3411");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-3411", "GOST3411");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + CryptoProObjectIdentifiers.gostR3411, "GOST3411");

            provider.addAlgorithm("SecretKeyFactory.PBEWITHHMACGOST3411", PREFIX + "$PBEWithMacKeyFactory");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + CryptoProObjectIdentifiers.gostR3411, "PBEWITHHMACGOST3411");

            addHMACAlgorithm(provider, "GOST3411", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
            addHMACAlias(provider, "GOST3411", CryptoProObjectIdentifiers.gostR3411);
        }
    }
}
