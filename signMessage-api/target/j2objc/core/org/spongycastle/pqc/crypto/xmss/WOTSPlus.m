//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/WOTSPlus.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/lang/Math.h"
#include "java/lang/NullPointerException.h"
#include "java/util/ArrayList.h"
#include "java/util/List.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/pqc/crypto/xmss/KeyedHashFunctions.h"
#include "org/spongycastle/pqc/crypto/xmss/OTSHashAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlus.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusPrivateKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusPublicKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusSignature.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSUtil.h"

@interface OrgSpongycastlePqcCryptoXmssWOTSPlus () {
 @public
  OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *params_;
  OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *khf_;
  IOSByteArray *secretKeySeed_;
  IOSByteArray *publicSeed_;
}

- (IOSByteArray *)chainWithByteArray:(IOSByteArray *)startHash
                             withInt:(jint)startIndex
                             withInt:(jint)steps
withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress;

- (id<JavaUtilList>)convertToBaseWWithByteArray:(IOSByteArray *)messageDigest
                                        withInt:(jint)w
                                        withInt:(jint)outLength;

- (IOSByteArray *)expandSecretKeySeedWithInt:(jint)index;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssWOTSPlus, params_, OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssWOTSPlus, khf_, OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssWOTSPlus, secretKeySeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssWOTSPlus, publicSeed_, IOSByteArray *)

__attribute__((unused)) static IOSByteArray *OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, IOSByteArray *startHash, jint startIndex, jint steps, OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress);

__attribute__((unused)) static id<JavaUtilList> OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, IOSByteArray *messageDigest, jint w, jint outLength);

__attribute__((unused)) static IOSByteArray *OrgSpongycastlePqcCryptoXmssWOTSPlus_expandSecretKeySeedWithInt_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, jint index);

@implementation OrgSpongycastlePqcCryptoXmssWOTSPlus

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters:(OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *)params {
  OrgSpongycastlePqcCryptoXmssWOTSPlus_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_(self, params);
  return self;
}

- (void)importKeysWithByteArray:(IOSByteArray *)secretKeySeed
                  withByteArray:(IOSByteArray *)publicSeed {
  if (secretKeySeed == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"secretKeySeed == null");
  }
  if (secretKeySeed->size_ != [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(params_)) getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of secretKeySeed needs to be equal to size of digest");
  }
  if (publicSeed == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"publicSeed == null");
  }
  if (publicSeed->size_ != [params_ getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of publicSeed needs to be equal to size of digest");
  }
  self->secretKeySeed_ = secretKeySeed;
  self->publicSeed_ = publicSeed;
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *)signWithByteArray:(IOSByteArray *)messageDigest
                      withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  if (messageDigest == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"messageDigest == null");
  }
  if (messageDigest->size_ != [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(params_)) getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of messageDigest needs to be equal to size of digest");
  }
  if (otsHashAddress == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress == null");
  }
  id<JavaUtilList> baseWMessage = OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(self, messageDigest, [params_ getWinternitzParameter], [params_ getLen1]);
  jint checksum = 0;
  for (jint i = 0; i < [params_ getLen1]; i++) {
    checksum += [params_ getWinternitzParameter] - 1 - [((JavaLangInteger *) nil_chk([((id<JavaUtilList>) nil_chk(baseWMessage)) getWithInt:i])) intValue];
  }
  JreLShiftAssignInt(&checksum, (8 - (([params_ getLen2] * OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_([params_ getWinternitzParameter])) % 8)));
  jint len2Bytes = JreFpToInt(JavaLangMath_ceilWithDouble_((jdouble) ([params_ getLen2] * OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_([params_ getWinternitzParameter])) / 8));
  id<JavaUtilList> baseWChecksum = OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(self, OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(checksum, len2Bytes), [params_ getWinternitzParameter], [params_ getLen2]);
  [((id<JavaUtilList>) nil_chk(baseWMessage)) addAllWithJavaUtilCollection:baseWChecksum];
  IOSObjectArray *signature = [IOSObjectArray newArrayWithLength:[params_ getLen] type:IOSClass_byteArray(1)];
  for (jint i = 0; i < [params_ getLen]; i++) {
    otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) getLayerAddress]])) withTreeAddressWithLong:[otsHashAddress getTreeAddress]])) withOTSAddressWithInt:[otsHashAddress getOTSAddress]])) withChainAddressWithInt:i])) withHashAddressWithInt:[otsHashAddress getHashAddress]])) withKeyAndMaskWithInt:[otsHashAddress getKeyAndMask]])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
    (void) IOSObjectArray_Set(signature, i, OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, OrgSpongycastlePqcCryptoXmssWOTSPlus_expandSecretKeySeedWithInt_(self, i), 0, [((JavaLangInteger *) nil_chk([baseWMessage getWithInt:i])) intValue], otsHashAddress));
  }
  return new_OrgSpongycastlePqcCryptoXmssWOTSPlusSignature_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(params_, signature);
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)messageDigest
withOrgSpongycastlePqcCryptoXmssWOTSPlusSignature:(OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *)signature
withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  if (messageDigest == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"messageDigest == null");
  }
  if (messageDigest->size_ != [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(params_)) getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of messageDigest needs to be equal to size of digest");
  }
  if (signature == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"signature == null");
  }
  if (otsHashAddress == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress == null");
  }
  IOSObjectArray *tmpPublicKey = [((OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *) nil_chk([self getPublicKeyFromSignatureWithByteArray:messageDigest withOrgSpongycastlePqcCryptoXmssWOTSPlusSignature:signature withOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress])) toByteArray];
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_areEqualWithByteArray2_withByteArray2_(tmpPublicKey, [((OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *) nil_chk([self getPublicKeyWithOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress])) toByteArray]) ? true : false;
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *)getPublicKeyFromSignatureWithByteArray:(IOSByteArray *)messageDigest
                                                  withOrgSpongycastlePqcCryptoXmssWOTSPlusSignature:(OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *)signature
                                                     withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  if (messageDigest == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"messageDigest == null");
  }
  if (messageDigest->size_ != [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(params_)) getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of messageDigest needs to be equal to size of digest");
  }
  if (signature == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"signature == null");
  }
  if (otsHashAddress == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress == null");
  }
  id<JavaUtilList> baseWMessage = OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(self, messageDigest, [params_ getWinternitzParameter], [params_ getLen1]);
  jint checksum = 0;
  for (jint i = 0; i < [params_ getLen1]; i++) {
    checksum += [params_ getWinternitzParameter] - 1 - [((JavaLangInteger *) nil_chk([((id<JavaUtilList>) nil_chk(baseWMessage)) getWithInt:i])) intValue];
  }
  JreLShiftAssignInt(&checksum, (8 - (([params_ getLen2] * OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_([params_ getWinternitzParameter])) % 8)));
  jint len2Bytes = JreFpToInt(JavaLangMath_ceilWithDouble_((jdouble) ([params_ getLen2] * OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_([params_ getWinternitzParameter])) / 8));
  id<JavaUtilList> baseWChecksum = OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(self, OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(checksum, len2Bytes), [params_ getWinternitzParameter], [params_ getLen2]);
  [((id<JavaUtilList>) nil_chk(baseWMessage)) addAllWithJavaUtilCollection:baseWChecksum];
  IOSObjectArray *publicKey = [IOSObjectArray newArrayWithLength:[params_ getLen] type:IOSClass_byteArray(1)];
  for (jint i = 0; i < [params_ getLen]; i++) {
    otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) getLayerAddress]])) withTreeAddressWithLong:[otsHashAddress getTreeAddress]])) withOTSAddressWithInt:[otsHashAddress getOTSAddress]])) withChainAddressWithInt:i])) withHashAddressWithInt:[otsHashAddress getHashAddress]])) withKeyAndMaskWithInt:[otsHashAddress getKeyAndMask]])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
    (void) IOSObjectArray_Set(publicKey, i, OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, IOSObjectArray_Get(nil_chk([signature toByteArray]), i), [((JavaLangInteger *) nil_chk([baseWMessage getWithInt:i])) intValue], [params_ getWinternitzParameter] - 1 - [((JavaLangInteger *) nil_chk([baseWMessage getWithInt:i])) intValue], otsHashAddress));
  }
  return new_OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(params_, publicKey);
}

- (IOSByteArray *)chainWithByteArray:(IOSByteArray *)startHash
                             withInt:(jint)startIndex
                             withInt:(jint)steps
withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  return OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, startHash, startIndex, steps, otsHashAddress);
}

- (id<JavaUtilList>)convertToBaseWWithByteArray:(IOSByteArray *)messageDigest
                                        withInt:(jint)w
                                        withInt:(jint)outLength {
  return OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(self, messageDigest, w, outLength);
}

- (IOSByteArray *)getWOTSPlusSecretKeyWithByteArray:(IOSByteArray *)secretKeySeed
     withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) getLayerAddress]])) withTreeAddressWithLong:[otsHashAddress getTreeAddress]])) withOTSAddressWithInt:[otsHashAddress getOTSAddress]])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
  return [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk(khf_)) PRFWithByteArray:secretKeySeed withByteArray:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) toByteArray]];
}

- (IOSByteArray *)expandSecretKeySeedWithInt:(jint)index {
  return OrgSpongycastlePqcCryptoXmssWOTSPlus_expandSecretKeySeedWithInt_(self, index);
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *)getParams {
  return params_;
}

- (OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *)getKhf {
  return khf_;
}

- (IOSByteArray *)getSecretKeySeed {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_([self getSecretKeySeed]);
}

- (IOSByteArray *)getPublicSeed {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(publicSeed_);
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters *)getPrivateKey {
  IOSObjectArray *privateKey = [IOSObjectArray newArrayWithLength:[((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(params_)) getLen] type:IOSClass_byteArray(1)];
  for (jint i = 0; i < privateKey->size_; i++) {
    (void) IOSObjectArray_Set(privateKey, i, OrgSpongycastlePqcCryptoXmssWOTSPlus_expandSecretKeySeedWithInt_(self, i));
  }
  return new_OrgSpongycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(params_, privateKey);
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *)getPublicKeyWithOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  if (otsHashAddress == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress == null");
  }
  IOSObjectArray *publicKey = [IOSObjectArray newArrayWithLength:[((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(params_)) getLen] type:IOSClass_byteArray(1)];
  for (jint i = 0; i < [params_ getLen]; i++) {
    otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) getLayerAddress]])) withTreeAddressWithLong:[otsHashAddress getTreeAddress]])) withOTSAddressWithInt:[otsHashAddress getOTSAddress]])) withChainAddressWithInt:i])) withHashAddressWithInt:[otsHashAddress getHashAddress]])) withKeyAndMaskWithInt:[otsHashAddress getKeyAndMask]])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
    (void) IOSObjectArray_Set(publicKey, i, OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, OrgSpongycastlePqcCryptoXmssWOTSPlus_expandSecretKeySeedWithInt_(self, i), 0, [params_ getWinternitzParameter] - 1, otsHashAddress));
  }
  return new_OrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(params_, publicKey);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusSignature;", 0x4, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 5, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters;", 0x4, 7, 6, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "LJavaUtilList;", 0x2, 10, 11, -1, 12, -1, -1 },
    { NULL, "[B", 0x4, 13, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 14, 15, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusParameters;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssKeyedHashFunctions;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusPublicKeyParameters;", 0x4, 16, 17, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters:);
  methods[1].selector = @selector(importKeysWithByteArray:withByteArray:);
  methods[2].selector = @selector(signWithByteArray:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  methods[3].selector = @selector(verifySignatureWithByteArray:withOrgSpongycastlePqcCryptoXmssWOTSPlusSignature:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  methods[4].selector = @selector(getPublicKeyFromSignatureWithByteArray:withOrgSpongycastlePqcCryptoXmssWOTSPlusSignature:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  methods[5].selector = @selector(chainWithByteArray:withInt:withInt:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  methods[6].selector = @selector(convertToBaseWWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(getWOTSPlusSecretKeyWithByteArray:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  methods[8].selector = @selector(expandSecretKeySeedWithInt:);
  methods[9].selector = @selector(getParams);
  methods[10].selector = @selector(getKhf);
  methods[11].selector = @selector(getSecretKeySeed);
  methods[12].selector = @selector(getPublicSeed);
  methods[13].selector = @selector(getPrivateKey);
  methods[14].selector = @selector(getPublicKeyWithOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastlePqcCryptoXmssWOTSPlusParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "khf_", "LOrgSpongycastlePqcCryptoXmssKeyedHashFunctions;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeySeed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcCryptoXmssWOTSPlusParameters;", "importKeys", "[B[B", "sign", "[BLOrgSpongycastlePqcCryptoXmssOTSHashAddress;", "verifySignature", "[BLOrgSpongycastlePqcCryptoXmssWOTSPlusSignature;LOrgSpongycastlePqcCryptoXmssOTSHashAddress;", "getPublicKeyFromSignature", "chain", "[BIILOrgSpongycastlePqcCryptoXmssOTSHashAddress;", "convertToBaseW", "[BII", "([BII)Ljava/util/List<Ljava/lang/Integer;>;", "getWOTSPlusSecretKey", "expandSecretKeySeed", "I", "getPublicKey", "LOrgSpongycastlePqcCryptoXmssOTSHashAddress;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssWOTSPlus = { "WOTSPlus", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 15, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssWOTSPlus;
}

@end

void OrgSpongycastlePqcCryptoXmssWOTSPlus_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *params) {
  NSObject_init(self);
  if (params == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  self->params_ = params;
  jint n = [params getDigestSize];
  self->khf_ = new_OrgSpongycastlePqcCryptoXmssKeyedHashFunctions_initWithOrgSpongycastleCryptoDigest_withInt_([params getDigest], n);
  self->secretKeySeed_ = [IOSByteArray newArrayWithLength:n];
  self->publicSeed_ = [IOSByteArray newArrayWithLength:n];
}

OrgSpongycastlePqcCryptoXmssWOTSPlus *new_OrgSpongycastlePqcCryptoXmssWOTSPlus_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_(OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssWOTSPlus, initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_, params)
}

OrgSpongycastlePqcCryptoXmssWOTSPlus *create_OrgSpongycastlePqcCryptoXmssWOTSPlus_initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_(OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssWOTSPlus, initWithOrgSpongycastlePqcCryptoXmssWOTSPlusParameters_, params)
}

IOSByteArray *OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, IOSByteArray *startHash, jint startIndex, jint steps, OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress) {
  jint n = [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(self->params_)) getDigestSize];
  if (startHash == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"startHash == null");
  }
  if (startHash->size_ != n) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$", @"startHash needs to be ", n, @"bytes"));
  }
  if (otsHashAddress == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress == null");
  }
  if ([otsHashAddress toByteArray] == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress byte array == null");
  }
  if ((startIndex + steps) > [self->params_ getWinternitzParameter] - 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"max chain length must not be greater than w");
  }
  if (steps == 0) {
    return startHash;
  }
  IOSByteArray *tmp = OrgSpongycastlePqcCryptoXmssWOTSPlus_chainWithByteArray_withInt_withInt_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, startHash, startIndex, steps - 1, otsHashAddress);
  otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:[otsHashAddress getLayerAddress]])) withTreeAddressWithLong:[otsHashAddress getTreeAddress]])) withOTSAddressWithInt:[otsHashAddress getOTSAddress]])) withChainAddressWithInt:[otsHashAddress getChainAddress]])) withHashAddressWithInt:startIndex + steps - 1])) withKeyAndMaskWithInt:0])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
  IOSByteArray *key = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk(self->khf_)) PRFWithByteArray:self->publicSeed_ withByteArray:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) toByteArray]];
  otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:[otsHashAddress getLayerAddress]])) withTreeAddressWithLong:[otsHashAddress getTreeAddress]])) withOTSAddressWithInt:[otsHashAddress getOTSAddress]])) withChainAddressWithInt:[otsHashAddress getChainAddress]])) withHashAddressWithInt:[otsHashAddress getHashAddress]])) withKeyAndMaskWithInt:1])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
  IOSByteArray *bitmask = [self->khf_ PRFWithByteArray:self->publicSeed_ withByteArray:[((OrgSpongycastlePqcCryptoXmssOTSHashAddress *) nil_chk(otsHashAddress)) toByteArray]];
  IOSByteArray *tmpMasked = [IOSByteArray newArrayWithLength:n];
  for (jint i = 0; i < n; i++) {
    *IOSByteArray_GetRef(tmpMasked, i) = (jbyte) (IOSByteArray_Get(nil_chk(tmp), i) ^ IOSByteArray_Get(nil_chk(bitmask), i));
  }
  tmp = [self->khf_ FWithByteArray:key withByteArray:tmpMasked];
  return tmp;
}

id<JavaUtilList> OrgSpongycastlePqcCryptoXmssWOTSPlus_convertToBaseWWithByteArray_withInt_withInt_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, IOSByteArray *messageDigest, jint w, jint outLength) {
  if (messageDigest == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"msg == null");
  }
  if (w != 4 && w != 16) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"w needs to be 4 or 16");
  }
  jint logW = OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_(w);
  if (outLength > ((8 * messageDigest->size_) / logW)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"outLength too big");
  }
  JavaUtilArrayList *res = new_JavaUtilArrayList_init();
  for (jint i = 0; i < messageDigest->size_; i++) {
    for (jint j = 8 - logW; j >= 0; j -= logW) {
      [res addWithId:JavaLangInteger_valueOfWithInt_((JreRShift32(IOSByteArray_Get(messageDigest, i), j)) & (w - 1))];
      if ([res size] == outLength) {
        return res;
      }
    }
  }
  return res;
}

IOSByteArray *OrgSpongycastlePqcCryptoXmssWOTSPlus_expandSecretKeySeedWithInt_(OrgSpongycastlePqcCryptoXmssWOTSPlus *self, jint index) {
  if (index < 0 || index >= [((OrgSpongycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk(self->params_)) getLen]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"index out of bounds");
  }
  return [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk(self->khf_)) PRFWithByteArray:self->secretKeySeed_ withByteArray:OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(index, 32)];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssWOTSPlus)