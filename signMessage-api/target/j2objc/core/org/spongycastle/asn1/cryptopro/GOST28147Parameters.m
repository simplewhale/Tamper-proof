//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cryptopro/GOST28147Parameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cryptopro/GOST28147Parameters.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleAsn1CryptoproGOST28147Parameters () {
 @public
  OrgSpongycastleAsn1ASN1OctetString *iv_;
  OrgSpongycastleAsn1ASN1ObjectIdentifier *paramSet_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CryptoproGOST28147Parameters, iv_, OrgSpongycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CryptoproGOST28147Parameters, paramSet_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

@implementation OrgSpongycastleAsn1CryptoproGOST28147Parameters

+ (OrgSpongycastleAsn1CryptoproGOST28147Parameters *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                            withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CryptoproGOST28147Parameters_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1CryptoproGOST28147Parameters *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CryptoproGOST28147Parameters_getInstanceWithId_(obj);
}

- (instancetype)initWithByteArray:(IOSByteArray *)iv
withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)paramSet {
  OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithByteArray_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(self, iv, paramSet);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:iv_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:paramSet_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getEncryptionParamSet {
  return paramSet_;
}

- (IOSByteArray *)getIV {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(iv_)) getOctets]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CryptoproGOST28147Parameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CryptoproGOST28147Parameters;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithByteArray:withOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(toASN1Primitive);
  methods[5].selector = @selector(getEncryptionParamSet);
  methods[6].selector = @selector(getIV);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "paramSet_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "[BLOrgSpongycastleAsn1ASN1ObjectIdentifier;", "LOrgSpongycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CryptoproGOST28147Parameters = { "GOST28147Parameters", "org.spongycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CryptoproGOST28147Parameters;
}

@end

OrgSpongycastleAsn1CryptoproGOST28147Parameters *OrgSpongycastleAsn1CryptoproGOST28147Parameters_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CryptoproGOST28147Parameters_initialize();
  return OrgSpongycastleAsn1CryptoproGOST28147Parameters_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1CryptoproGOST28147Parameters *OrgSpongycastleAsn1CryptoproGOST28147Parameters_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CryptoproGOST28147Parameters_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CryptoproGOST28147Parameters class]]) {
    return (OrgSpongycastleAsn1CryptoproGOST28147Parameters *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithByteArray_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1CryptoproGOST28147Parameters *self, IOSByteArray *iv, OrgSpongycastleAsn1ASN1ObjectIdentifier *paramSet) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->iv_ = new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(iv);
  self->paramSet_ = paramSet;
}

OrgSpongycastleAsn1CryptoproGOST28147Parameters *new_OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithByteArray_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(IOSByteArray *iv, OrgSpongycastleAsn1ASN1ObjectIdentifier *paramSet) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproGOST28147Parameters, initWithByteArray_withOrgSpongycastleAsn1ASN1ObjectIdentifier_, iv, paramSet)
}

OrgSpongycastleAsn1CryptoproGOST28147Parameters *create_OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithByteArray_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(IOSByteArray *iv, OrgSpongycastleAsn1ASN1ObjectIdentifier *paramSet) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproGOST28147Parameters, initWithByteArray_withOrgSpongycastleAsn1ASN1ObjectIdentifier_, iv, paramSet)
}

void OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CryptoproGOST28147Parameters *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->iv_ = (OrgSpongycastleAsn1ASN1OctetString *) cast_chk([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], [OrgSpongycastleAsn1ASN1OctetString class]);
  self->paramSet_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
}

OrgSpongycastleAsn1CryptoproGOST28147Parameters *new_OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproGOST28147Parameters, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CryptoproGOST28147Parameters *create_OrgSpongycastleAsn1CryptoproGOST28147Parameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproGOST28147Parameters, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CryptoproGOST28147Parameters)