//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/AEADParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/params/AEADParameters.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"

@interface OrgSpongycastleCryptoParamsAEADParameters () {
 @public
  IOSByteArray *associatedText_;
  IOSByteArray *nonce_;
  OrgSpongycastleCryptoParamsKeyParameter *key_;
  jint macSize_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsAEADParameters, associatedText_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsAEADParameters, nonce_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsAEADParameters, key_, OrgSpongycastleCryptoParamsKeyParameter *)

@implementation OrgSpongycastleCryptoParamsAEADParameters

- (instancetype)initWithOrgSpongycastleCryptoParamsKeyParameter:(OrgSpongycastleCryptoParamsKeyParameter *)key
                                                        withInt:(jint)macSize
                                                  withByteArray:(IOSByteArray *)nonce {
  OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_(self, key, macSize, nonce);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoParamsKeyParameter:(OrgSpongycastleCryptoParamsKeyParameter *)key
                                                        withInt:(jint)macSize
                                                  withByteArray:(IOSByteArray *)nonce
                                                  withByteArray:(IOSByteArray *)associatedText {
  OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(self, key, macSize, nonce, associatedText);
  return self;
}

- (OrgSpongycastleCryptoParamsKeyParameter *)getKey {
  return key_;
}

- (jint)getMacSize {
  return macSize_;
}

- (IOSByteArray *)getAssociatedText {
  return associatedText_;
}

- (IOSByteArray *)getNonce {
  return nonce_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsKeyParameter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoParamsKeyParameter:withInt:withByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoParamsKeyParameter:withInt:withByteArray:withByteArray:);
  methods[2].selector = @selector(getKey);
  methods[3].selector = @selector(getMacSize);
  methods[4].selector = @selector(getAssociatedText);
  methods[5].selector = @selector(getNonce);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "associatedText_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nonce_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "LOrgSpongycastleCryptoParamsKeyParameter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "macSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoParamsKeyParameter;I[B", "LOrgSpongycastleCryptoParamsKeyParameter;I[B[B" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsAEADParameters = { "AEADParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 6, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsAEADParameters;
}

@end

void OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_(OrgSpongycastleCryptoParamsAEADParameters *self, OrgSpongycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce) {
  OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(self, key, macSize, nonce, nil);
}

OrgSpongycastleCryptoParamsAEADParameters *new_OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_(OrgSpongycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsAEADParameters, initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_, key, macSize, nonce)
}

OrgSpongycastleCryptoParamsAEADParameters *create_OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_(OrgSpongycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsAEADParameters, initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_, key, macSize, nonce)
}

void OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(OrgSpongycastleCryptoParamsAEADParameters *self, OrgSpongycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce, IOSByteArray *associatedText) {
  NSObject_init(self);
  self->key_ = key;
  self->nonce_ = nonce;
  self->macSize_ = macSize;
  self->associatedText_ = associatedText;
}

OrgSpongycastleCryptoParamsAEADParameters *new_OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(OrgSpongycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce, IOSByteArray *associatedText) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsAEADParameters, initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_, key, macSize, nonce, associatedText)
}

OrgSpongycastleCryptoParamsAEADParameters *create_OrgSpongycastleCryptoParamsAEADParameters_initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(OrgSpongycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce, IOSByteArray *associatedText) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsAEADParameters, initWithOrgSpongycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_, key, macSize, nonce, associatedText)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsAEADParameters)
