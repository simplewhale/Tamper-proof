//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSPublicKeyParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSPublicKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSUtil.h"

@interface OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters () {
 @public
  OrgSpongycastlePqcCryptoXmssXMSSParameters *params_;
  IOSByteArray *root_;
  IOSByteArray *publicSeed_;
}

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder:(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)builder;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters, params_, OrgSpongycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters, publicSeed_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *self, OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder);

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *new_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *create_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder);

@interface OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder () {
 @public
  OrgSpongycastlePqcCryptoXmssXMSSParameters *params_;
  IOSByteArray *root_;
  IOSByteArray *publicSeed_;
  IOSByteArray *publicKey_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, params_, OrgSpongycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, publicKey_, IOSByteArray *)

@implementation OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder:(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)builder {
  OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(self, builder);
  return self;
}

- (IOSByteArray *)toByteArray {
  jint n = [((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getDigestSize];
  jint rootSize = n;
  jint publicSeedSize = n;
  jint totalSize = rootSize + publicSeedSize;
  IOSByteArray *out = [IOSByteArray newArrayWithLength:totalSize];
  jint position = 0;
  OrgSpongycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, root_, position);
  position += rootSize;
  OrgSpongycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, publicSeed_, position);
  return out;
}

- (IOSByteArray *)getRoot {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(root_);
}

- (IOSByteArray *)getPublicSeed {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(publicSeed_);
}

- (OrgSpongycastlePqcCryptoXmssXMSSParameters *)getParameters {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder:);
  methods[1].selector = @selector(toByteArray);
  methods[2].selector = @selector(getRoot);
  methods[3].selector = @selector(getPublicSeed);
  methods[4].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters = { "XMSSPublicKeyParameters", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x11, 5, 3, -1, 0, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters;
}

@end

void OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *self, OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) {
  OrgSpongycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, false);
  self->params_ = ((OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *) nil_chk(builder))->params_;
  if (self->params_ == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  jint n = [self->params_ getDigestSize];
  IOSByteArray *publicKey = builder->publicKey_;
  if (publicKey != nil) {
    jint rootSize = n;
    jint publicSeedSize = n;
    jint totalSize = rootSize + publicSeedSize;
    if (publicKey->size_ != totalSize) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"public key has wrong size");
    }
    jint position = 0;
    self->root_ = OrgSpongycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(publicKey, position, rootSize);
    position += rootSize;
    self->publicSeed_ = OrgSpongycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(publicKey, position, publicSeedSize);
  }
  else {
    IOSByteArray *tmpRoot = builder->root_;
    if (tmpRoot != nil) {
      if (tmpRoot->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"length of root must be equal to length of digest");
      }
      self->root_ = tmpRoot;
    }
    else {
      self->root_ = [IOSByteArray newArrayWithLength:n];
    }
    IOSByteArray *tmpPublicSeed = builder->publicSeed_;
    if (tmpPublicSeed != nil) {
      if (tmpPublicSeed->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"length of publicSeed must be equal to length of digest");
      }
      self->publicSeed_ = tmpPublicSeed;
    }
    else {
      self->publicSeed_ = [IOSByteArray newArrayWithLength:n];
    }
  }
}

OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *new_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters, initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_, builder)
}

OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *create_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters, initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_, builder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters)

@implementation OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSParameters:(OrgSpongycastlePqcCryptoXmssXMSSParameters *)params {
  OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(self, params);
  return self;
}

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withRootWithByteArray:(IOSByteArray *)val {
  root_ = OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withPublicSeedWithByteArray:(IOSByteArray *)val {
  publicSeed_ = OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withPublicKeyWithByteArray:(IOSByteArray *)val {
  publicKey_ = OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters *)build {
  return new_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;", 0x1, 3, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;", 0x1, 4, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssXMSSParameters:);
  methods[1].selector = @selector(withRootWithByteArray:);
  methods[2].selector = @selector(withPublicSeedWithByteArray:);
  methods[3].selector = @selector(withPublicKeyWithByteArray:);
  methods[4].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", "withRoot", "[B", "withPublicSeed", "withPublicKey", "LOrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder = { "Builder", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x9, 5, 4, 5, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;
}

@end

void OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *self, OrgSpongycastlePqcCryptoXmssXMSSParameters *params) {
  NSObject_init(self);
  self->root_ = nil;
  self->publicSeed_ = nil;
  self->publicKey_ = nil;
  self->params_ = params;
}

OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *new_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(OrgSpongycastlePqcCryptoXmssXMSSParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_, params)
}

OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *create_OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_(OrgSpongycastlePqcCryptoXmssXMSSParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, initWithOrgSpongycastlePqcCryptoXmssXMSSParameters_, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder)