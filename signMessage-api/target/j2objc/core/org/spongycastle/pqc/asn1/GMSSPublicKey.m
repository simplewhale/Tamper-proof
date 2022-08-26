//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/asn1/GMSSPublicKey.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/pqc/asn1/GMSSPublicKey.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastlePqcAsn1GMSSPublicKey () {
 @public
  OrgSpongycastleAsn1ASN1Integer *version__;
  IOSByteArray *publicKey_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1GMSSPublicKey, version__, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1GMSSPublicKey, publicKey_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastlePqcAsn1GMSSPublicKey *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastlePqcAsn1GMSSPublicKey *new_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcAsn1GMSSPublicKey *create_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastlePqcAsn1GMSSPublicKey

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)publicKeyBytes {
  OrgSpongycastlePqcAsn1GMSSPublicKey_initWithByteArray_(self, publicKeyBytes);
  return self;
}

+ (OrgSpongycastlePqcAsn1GMSSPublicKey *)getInstanceWithId:(id)o {
  return OrgSpongycastlePqcAsn1GMSSPublicKey_getInstanceWithId_(o);
}

- (IOSByteArray *)getPublicKey {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(publicKey_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:version__];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(publicKey_)];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcAsn1GMSSPublicKey;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithByteArray:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getPublicKey);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 4, -1, -1, -1 },
    { "publicKey_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "[B", "getInstance", "LNSObject;", "version" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcAsn1GMSSPublicKey = { "GMSSPublicKey", "org.spongycastle.pqc.asn1", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcAsn1GMSSPublicKey;
}

@end

void OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastlePqcAsn1GMSSPublicKey *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"size of seq = ", [seq size]));
  }
  self->version__ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->publicKey_ = [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets];
}

OrgSpongycastlePqcAsn1GMSSPublicKey *new_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcAsn1GMSSPublicKey, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastlePqcAsn1GMSSPublicKey *create_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcAsn1GMSSPublicKey, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastlePqcAsn1GMSSPublicKey_initWithByteArray_(OrgSpongycastlePqcAsn1GMSSPublicKey *self, IOSByteArray *publicKeyBytes) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0);
  self->publicKey_ = publicKeyBytes;
}

OrgSpongycastlePqcAsn1GMSSPublicKey *new_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithByteArray_(IOSByteArray *publicKeyBytes) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcAsn1GMSSPublicKey, initWithByteArray_, publicKeyBytes)
}

OrgSpongycastlePqcAsn1GMSSPublicKey *create_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithByteArray_(IOSByteArray *publicKeyBytes) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcAsn1GMSSPublicKey, initWithByteArray_, publicKeyBytes)
}

OrgSpongycastlePqcAsn1GMSSPublicKey *OrgSpongycastlePqcAsn1GMSSPublicKey_getInstanceWithId_(id o) {
  OrgSpongycastlePqcAsn1GMSSPublicKey_initialize();
  if ([o isKindOfClass:[OrgSpongycastlePqcAsn1GMSSPublicKey class]]) {
    return (OrgSpongycastlePqcAsn1GMSSPublicKey *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastlePqcAsn1GMSSPublicKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcAsn1GMSSPublicKey)
