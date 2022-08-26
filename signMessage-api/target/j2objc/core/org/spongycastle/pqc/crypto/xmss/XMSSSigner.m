//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSSigner.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/NullPointerException.h"
#include "java/util/List.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/pqc/crypto/xmss/BDS.h"
#include "org/spongycastle/pqc/crypto/xmss/KeyedHashFunctions.h"
#include "org/spongycastle/pqc/crypto/xmss/OTSHashAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlus.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusSignature.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSAddress.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSNode.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSPrivateKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSPublicKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSReducedSignature.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSSignature.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSSigner.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSUtil.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSVerifierUtil.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastlePqcCryptoXmssXMSSSigner () {
 @public
  OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *privateKey_;
  OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *nextKeyGenerator_;
  OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *publicKey_;
  OrgSpongycastlePqcCryptoXmssXMSSParameters *params_;
  OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *khf_;
  jboolean initSign_;
  jboolean hasGenerated_;
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *)wotsSignWithByteArray:(IOSByteArray *)messageDigest
                          withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSSigner, privateKey_, OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSSigner, nextKeyGenerator_, OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSSigner, publicKey_, OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSSigner, params_, OrgSpongycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSSigner, khf_, OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *)

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *OrgSpongycastlePqcCryptoXmssXMSSSigner_wotsSignWithByteArray_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(OrgSpongycastlePqcCryptoXmssXMSSSigner *self, IOSByteArray *messageDigest, OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress);

@implementation OrgSpongycastlePqcCryptoXmssXMSSSigner

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoXmssXMSSSigner_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  if (forSigning) {
    initSign_ = true;
    hasGenerated_ = false;
    privateKey_ = (OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) cast_chk(param, [OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters class]);
    nextKeyGenerator_ = privateKey_;
    params_ = [((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(privateKey_)) getParameters];
    khf_ = [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getWOTSPlus])) getKhf];
  }
  else {
    initSign_ = false;
    publicKey_ = (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *) cast_chk(param, [OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters class]);
    params_ = [((OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(publicKey_)) getParameters];
    khf_ = [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getWOTSPlus])) getKhf];
  }
}

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message {
  if (message == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"message == null");
  }
  if (initSign_) {
    if (privateKey_ == nil) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"signing key no longer usable");
    }
  }
  else {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"signer not initialized for signature generation");
  }
  if ([((id<JavaUtilList>) nil_chk([((OrgSpongycastlePqcCryptoXmssBDS *) nil_chk([privateKey_ getBDSState])) getAuthenticationPath])) isEmpty]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not initialized");
  }
  jint index = [((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(privateKey_)) getIndex];
  if (!OrgSpongycastlePqcCryptoXmssXMSSUtil_isIndexValidWithInt_withLong_([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getHeight], index)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"index out of bounds");
  }
  IOSByteArray *random = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk(khf_)) PRFWithByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(privateKey_)) getSecretKeyPRF] withByteArray:OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(index, 32)];
  IOSByteArray *concatenated = OrgSpongycastleUtilArrays_concatenateWithByteArray_withByteArray_withByteArray_(random, [((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(privateKey_)) getRoot], OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(index, [((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getDigestSize]));
  IOSByteArray *messageDigest = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk(khf_)) HMsgWithByteArray:concatenated withByteArray:message];
  OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withOTSAddressWithInt:index])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
  OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *wotsPlusSignature = OrgSpongycastlePqcCryptoXmssXMSSSigner_wotsSignWithByteArray_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, messageDigest, otsHashAddress);
  OrgSpongycastlePqcCryptoXmssXMSSSignature *signature = (OrgSpongycastlePqcCryptoXmssXMSSSignature *) cast_chk([((OrgSpongycastlePqcCryptoXmssXMSSReducedSignature_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSReducedSignature_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSSignature_Builder *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSSignature_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssXMSSSignature_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(params_) withIndexWithInt:index])) withRandomWithByteArray:random])) withWOTSPlusSignatureWithOrgSpongycastlePqcCryptoXmssWOTSPlusSignature:wotsPlusSignature])) withAuthPathWithJavaUtilList:[((OrgSpongycastlePqcCryptoXmssBDS *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(privateKey_)) getBDSState])) getAuthenticationPath]])) build], [OrgSpongycastlePqcCryptoXmssXMSSSignature class]);
  hasGenerated_ = true;
  if (nextKeyGenerator_ != nil) {
    privateKey_ = [nextKeyGenerator_ getNextKey];
    nextKeyGenerator_ = privateKey_;
  }
  else {
    privateKey_ = nil;
  }
  return [((OrgSpongycastlePqcCryptoXmssXMSSSignature *) nil_chk(signature)) toByteArray];
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature {
  OrgSpongycastlePqcCryptoXmssXMSSSignature *sig = [((OrgSpongycastlePqcCryptoXmssXMSSSignature_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssXMSSSignature_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(params_) withSignatureWithByteArray:signature])) build];
  jint index = [((OrgSpongycastlePqcCryptoXmssXMSSSignature *) nil_chk(sig)) getIndex];
  [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getWOTSPlus])) importKeysWithByteArray:[IOSByteArray newArrayWithLength:[((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getDigestSize]] withByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(publicKey_)) getPublicSeed]];
  IOSByteArray *concatenated = OrgSpongycastleUtilArrays_concatenateWithByteArray_withByteArray_withByteArray_([sig getRandom], [((OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(publicKey_)) getRoot], OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(index, [((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getDigestSize]));
  IOSByteArray *messageDigest = [((OrgSpongycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk(khf_)) HMsgWithByteArray:concatenated withByteArray:message];
  jint xmssHeight = [((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getHeight];
  jint indexLeaf = OrgSpongycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(index, xmssHeight);
  OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress = (OrgSpongycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssOTSHashAddress_Builder_init() withOTSAddressWithInt:index])) build], [OrgSpongycastlePqcCryptoXmssOTSHashAddress class]);
  OrgSpongycastlePqcCryptoXmssXMSSNode *rootNodeFromSignature = OrgSpongycastlePqcCryptoXmssXMSSVerifierUtil_getRootNodeFromSignatureWithOrgSpongycastlePqcCryptoXmssWOTSPlus_withInt_withByteArray_withOrgSpongycastlePqcCryptoXmssXMSSReducedSignature_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_withInt_([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getWOTSPlus], xmssHeight, messageDigest, sig, otsHashAddress, indexLeaf);
  return OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_([((OrgSpongycastlePqcCryptoXmssXMSSNode *) nil_chk(rootNodeFromSignature)) getValue], [((OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(publicKey_)) getRoot]);
}

- (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)getUpdatedPrivateKey {
  if (hasGenerated_) {
    OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *privKey = privateKey_;
    privateKey_ = nil;
    nextKeyGenerator_ = nil;
    return privKey;
  }
  else {
    OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *privKey = [((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(nextKeyGenerator_)) getNextKey];
    nextKeyGenerator_ = nil;
    return privKey;
  }
}

- (OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *)wotsSignWithByteArray:(IOSByteArray *)messageDigest
                          withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  return OrgSpongycastlePqcCryptoXmssXMSSSigner_wotsSignWithByteArray_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(self, messageDigest, otsHashAddress);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusSignature;", 0x2, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(generateSignatureWithByteArray:);
  methods[3].selector = @selector(verifySignatureWithByteArray:withByteArray:);
  methods[4].selector = @selector(getUpdatedPrivateKey);
  methods[5].selector = @selector(wotsSignWithByteArray:withOrgSpongycastlePqcCryptoXmssOTSHashAddress:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privateKey_", "LOrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nextKeyGenerator_", "LOrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "params_", "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "khf_", "LOrgSpongycastlePqcCryptoXmssKeyedHashFunctions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initSign_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hasGenerated_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "generateSignature", "[B", "verifySignature", "[B[B", "wotsSign", "[BLOrgSpongycastlePqcCryptoXmssOTSHashAddress;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssXMSSSigner = { "XMSSSigner", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x1, 6, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssXMSSSigner;
}

@end

void OrgSpongycastlePqcCryptoXmssXMSSSigner_init(OrgSpongycastlePqcCryptoXmssXMSSSigner *self) {
  NSObject_init(self);
}

OrgSpongycastlePqcCryptoXmssXMSSSigner *new_OrgSpongycastlePqcCryptoXmssXMSSSigner_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssXMSSSigner, init)
}

OrgSpongycastlePqcCryptoXmssXMSSSigner *create_OrgSpongycastlePqcCryptoXmssXMSSSigner_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssXMSSSigner, init)
}

OrgSpongycastlePqcCryptoXmssWOTSPlusSignature *OrgSpongycastlePqcCryptoXmssXMSSSigner_wotsSignWithByteArray_withOrgSpongycastlePqcCryptoXmssOTSHashAddress_(OrgSpongycastlePqcCryptoXmssXMSSSigner *self, IOSByteArray *messageDigest, OrgSpongycastlePqcCryptoXmssOTSHashAddress *otsHashAddress) {
  if (((IOSByteArray *) nil_chk(messageDigest))->size_ != [((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(self->params_)) getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"size of messageDigest needs to be equal to size of digest");
  }
  if (otsHashAddress == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"otsHashAddress == null");
  }
  [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(self->params_)) getWOTSPlus])) importKeysWithByteArray:[((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(self->params_)) getWOTSPlus])) getWOTSPlusSecretKeyWithByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(self->privateKey_)) getSecretKeySeed] withOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress] withByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(self->privateKey_)) getPublicSeed]];
  return [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(self->params_)) getWOTSPlus])) signWithByteArray:messageDigest withOrgSpongycastlePqcCryptoXmssOTSHashAddress:otsHashAddress];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssXMSSSigner)