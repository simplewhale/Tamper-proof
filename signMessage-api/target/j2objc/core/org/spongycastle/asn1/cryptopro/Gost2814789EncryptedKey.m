//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cryptopro/Gost2814789EncryptedKey.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cryptopro/Gost2814789EncryptedKey.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey () {
 @public
  IOSByteArray *encryptedKey_;
  IOSByteArray *maskKey_;
  IOSByteArray *macKey_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, encryptedKey_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, maskKey_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, macKey_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *new_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *create_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_getInstanceWithId_(obj);
}

- (instancetype)initWithByteArray:(IOSByteArray *)encryptedKey
                    withByteArray:(IOSByteArray *)macKey {
  OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(self, encryptedKey, macKey);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encryptedKey
                    withByteArray:(IOSByteArray *)maskKey
                    withByteArray:(IOSByteArray *)macKey {
  OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(self, encryptedKey, maskKey, macKey);
  return self;
}

- (IOSByteArray *)getEncryptedKey {
  return encryptedKey_;
}

- (IOSByteArray *)getMaskKey {
  return maskKey_;
}

- (IOSByteArray *)getMacKey {
  return macKey_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(encryptedKey_)];
  if (maskKey_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(encryptedKey_))];
  }
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(macKey_)];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CryptoproGost2814789EncryptedKey;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithByteArray:withByteArray:);
  methods[3].selector = @selector(initWithByteArray:withByteArray:withByteArray:);
  methods[4].selector = @selector(getEncryptedKey);
  methods[5].selector = @selector(getMaskKey);
  methods[6].selector = @selector(getMacKey);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encryptedKey_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "maskKey_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "macKey_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "[B[B", "[B[B[B" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey = { "Gost2814789EncryptedKey", "org.spongycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey;
}

@end

void OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 2) {
    self->encryptedKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:0]))) getOctets]);
    self->macKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets]);
    self->maskKey_ = nil;
  }
  else if ([seq size] == 3) {
    self->encryptedKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:0]))) getOctets]);
    self->maskKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_([seq getObjectAtWithInt:1]), false))) getOctets]);
    self->macKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]))) getOctets]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown sequence length: ", [seq size]));
  }
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *new_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *create_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey class]]) {
    return (OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *self, IOSByteArray *encryptedKey, IOSByteArray *macKey) {
  OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(self, encryptedKey, nil, macKey);
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *new_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *macKey) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_, encryptedKey, macKey)
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *create_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *macKey) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_, encryptedKey, macKey)
}

void OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *self, IOSByteArray *encryptedKey, IOSByteArray *maskKey, IOSByteArray *macKey) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->encryptedKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(encryptedKey);
  self->maskKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(maskKey);
  self->macKey_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(macKey);
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *new_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *maskKey, IOSByteArray *macKey) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_withByteArray_, encryptedKey, maskKey, macKey)
}

OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey *create_OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *maskKey, IOSByteArray *macKey) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_withByteArray_, encryptedKey, maskKey, macKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CryptoproGost2814789EncryptedKey)
