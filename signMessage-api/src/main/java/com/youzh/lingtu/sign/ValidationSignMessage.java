package com.youzh.lingtu.sign;

import com.youzh.lingtu.genkey.GenerateMnemonic;
import com.youzh.lingtu.sign.crypto.*;
import com.youzh.lingtu.sign.crypto.utils.Assertions;
import com.youzh.lingtu.sign.crypto.utils.Numeric;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip39.wordlists.English;
import io.github.novacrypto.hashing.Sha256;
import org.apache.commons.codec.binary.Base64;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.custom.sec.SecP256K1Curve;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.youzh.lingtu.genkey.GenerateMnemonic.genMnemonic;


/**
 * @author alen
 */
public class ValidationSignMessage {

    private static final String ETHPASSPHASE = "akushgdiuqe";
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

    private String publicKey;
    private String privateKey;

    /**
     * 签名消息
     * @param message 消息
     * @param privateKey 私钥
     * @return 网络传送内容
     */
   public static String signMessage(String message,String privateKey){

       Credentials credentials = Credentials.create(privateKey);
       ECKeyPair ecKeyPair = credentials.getEcKeyPair();
       byte[] bMessage = message.getBytes();
       byte[] signMessage = signMessage(bMessage,ecKeyPair);
       return Numeric.toHexStringNoPrefix(signMessage);
   }


    public static Boolean validSigMessage(String message,String signMessage,String publicKey){
        byte[] by = Numeric.hexStringToByteArray(signMessage);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        //复原r v
        System.arraycopy(by, 0, r, 0, r.length);
        System.arraycopy(by, 32, s, 0, s.length);

        try {
            BigInteger key1 = Sign.signedMessageToKey(message.getBytes(),new Sign.SignatureData((byte) 28,r,s));
            BigInteger key2 = Sign.signedMessageToKey(message.getBytes(),new Sign.SignatureData((byte) 27,r,s));
            BigInteger pub = Numeric.toBigInt(publicKey);
            if (pub.equals(key1) || pub.equals(key2)){
                return true;
            }
        } catch (SignatureException e) {
            e.printStackTrace();
        }
            return false;
    }

    /**
     * 生成eth公私钥对
     * @param mnemonic 助记词
     * @return map
     */
    public static ValidationSignMessage genKey(String mnemonic) {
        try {

            List mnemonicList = Arrays.asList(mnemonic.split(" "));
            byte[] seed = new SeedCalculator()
                    .withWordsFromWordList(English.INSTANCE)
                    .calculateSeed(mnemonicList, ETHPASSPHASE);
            ECKeyPair ecKeyPair = ECKeyPair.create(Sha256.sha256(seed));
            String privateKey = ecKeyPair.getPrivateKey().toString(16);
            String publicKey = ecKeyPair.getPublicKey().toString(16);
            ValidationSignMessage vm = new ValidationSignMessage();
            vm.setPublicKey(publicKey);
            vm.setPrivateKey(privateKey);
            return vm;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 签名信息
     * @param message 信息
     * @param keyPair keypair
     * @return 待序列化byte数组
     */
    private static byte[] signMessage(byte[] message, ECKeyPair keyPair) {
        BigInteger publicKey = keyPair.getPublicKey();
        byte[] messageHash = Hash.sha3(message);
        ECDSASignature sig = keyPair.sign(messageHash);
        int recId = -1;

        int headerByte;
        for(headerByte = 0; headerByte < 4; ++headerByte) {
            BigInteger k = recoverFromSignature(headerByte, sig, messageHash);
            if (k != null && k.equals(publicKey)) {
                recId = headerByte;
                break;
            }
        }

        if (recId == -1) {
            throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
        } else {
            byte[] r = Numeric.toBytesPadded(sig.r, 32);
            byte[] s = Numeric.toBytesPadded(sig.s, 32);
            byte[] bt = new byte[r.length+s.length];
            System.arraycopy(r, 0, bt, 0, s.length);
            System.arraycopy(s, 0, bt, r.length, s.length);
            return bt;
        }
    }

    private static BigInteger recoverFromSignature(int recId, ECDSASignature sig, byte[] message) {
        Assertions.verifyPrecondition(recId >= 0, "recId must be positive");
        Assertions.verifyPrecondition(sig.r.signum() >= 0, "r must be positive");
        Assertions.verifyPrecondition(sig.s.signum() >= 0, "s must be positive");
        Assertions.verifyPrecondition(message != null, "message cannot be null");
        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf((long)recId / 2L);
        BigInteger x = sig.r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        } else {
            ECPoint R = decompressKey(x, (recId & 1) == 1);
            if (!R.multiply(n).isInfinity()) {
                return null;
            } else {
                BigInteger e = new BigInteger(1, message);
                BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
                BigInteger rInv = sig.r.modInverse(n);
                BigInteger srInv = rInv.multiply(sig.s).mod(n);
                BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
                ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
                byte[] qBytes = q.getEncoded(false);
                return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
            }
        }
    }

    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte)(yBit ? 3 : 2);
        return CURVE.getCurve().decodePoint(compEnc);
    }

    /**
     * 随机生成密钥对
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static Map<String,String> genKeyPair() throws NoSuchAlgorithmException {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为96-1024位
        SecureRandom secureRandom = new SecureRandom();
        keyPairGen.initialize(1024, secureRandom);
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // 得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        // 得到公钥
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        // 得到公钥字符串
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        // 得到私钥字符串
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
        // 将公钥和私钥保存
        Map<String,String> map = new HashMap<>(2);
        map.put("publicKey",publicKeyString);
        map.put("privateKey",privateKeyString);

        return map;
    }

    public void setPublicKey(String publicKey){
        this.publicKey = publicKey;
    }
    public String getPublicKey(){
        return this.publicKey;
    }
    public void setPrivateKey(String privateKey){
        this.privateKey = privateKey;
    }
    public String getPrivateKey(){
        return this.privateKey;
    }


    public static void main(String[] args) {
        //String me = genMnemonic();
        //ValidationSignMessage v = genKey(me);
        //9d44df49c78b2b9953145cdb1a7d7cf0298fdac79cc9fcbde4a6b1fcc6527c8d
        //System.out.println(v.getPrivateKey());
        //2f72e8c57ecb4b4f6749ac7f07fc9f212a5060c4e91b796c0758148eea4573e7cd06b6702faea420154883fa8f246bbdd05c5d7576245b8ad6355bfd3a72d1a4
        //System.out.println(v.getPublicKey());
        String pri = "9d44df49c78b2b9953145cdb1a7d7cf0298fdac79cc9fcbde4a6b1fcc6527c8d";
        String pub = "2f72e8c57ecb4b4f6749ac7f07fc9f212a5060c4e91b796c0758148eea4573e7cd06b6702faea420154883fa8f246bbdd05c5d7576245b8ad6355bfd3a72d1a4";
        String msg = "hello word";
        String sigm = signMessage(msg,pri);
        System.out.println(validSigMessage(msg,sigm,pub)); //true
        System.out.println(validSigMessage("hello",sigm,pub));//false

//        z
        //{privateKey=MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALfMUYgNST33PueHfKqcfM/kY4Hub3hZX16nRyKizVlbgAUnFuqD/gWJIo0w4C0nywgE31nmCwWdtPlDpOyEw1MNPoxc5CN+ODvtPLYrbwtOrFLm/d9ELxORqnPvl89A+G+M2XFE/lKjetTxa4R9EvIpAwqZJ1a3wlcCYIPcAu39AgMBAAECgYA6HhZN0f2t5WdzqKjn/fGNfydj53RB9uisMnLQ5e/O6Jrzhie94hzJvVI6mRDZ1nJhx8CkWZR0oyidhSE6VMS6DfyRUC+8/X33W2KF0/EPX0y0xQ76A4PRDhYxeW93ErOPjAfdJjRSPjI7CahODOzels+EIBo+JQz9CBojQLmKVQJBAOBnCwalv3LgjXMIhWZDO25hIe7QiavJtZ88jCL6Gokjty0eQtYnLp6gKJGC00h8BR+2vsMW0FMsoz9z6kjuvKsCQQDRrZ+X7R2Nhf8UQKcJQJMBonelcwgPI6CbdUkvl6iouittKqgNNJnmuw7bhoLEHNSnlMZJvMpYcJEYuqA8Fq/3AkBBnX+42uBHG+fgWf5/r2sCVH6SkQGgbKOhwxeK5qy5qurV04JhkiVslpImMiXLjRAGfO38p4AUwfmeBSvdVYlvAkEAiBoXOdqkEDUmOdMtmYfc5Ha9Cxv74zfRDJe5Bbd/tuYBQj8qDkhSjb5mCoDpaLr+Hjkn7L0q6vVGebLKR7bCSQJAflpopTJm5jyUlm38dUlLzLpkoDjRNcOtEUdFT17lothIIv9VlBVJMAmWY+RTkISi3tHtgTTADOLla3n5w/C3ow==, publicKey=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3zFGIDUk99z7nh3yqnHzP5GOB7m94WV9ep0cios1ZW4AFJxbqg/4FiSKNMOAtJ8sIBN9Z5gsFnbT5Q6TshMNTDT6MXOQjfjg77Ty2K28LTqxS5v3fRC8Tkapz75fPQPhvjNlxRP5So3rU8WuEfRLyKQMKmSdWt8JXAmCD3ALt/QIDAQAB}

    }
}

