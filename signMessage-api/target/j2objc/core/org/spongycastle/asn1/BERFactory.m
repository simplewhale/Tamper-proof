//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/BERFactory.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/BERFactory.h"
#include "org/spongycastle/asn1/BERSequence.h"
#include "org/spongycastle/asn1/BERSet.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1BERFactory)

OrgSpongycastleAsn1BERSequence *OrgSpongycastleAsn1BERFactory_EMPTY_SEQUENCE;
OrgSpongycastleAsn1BERSet *OrgSpongycastleAsn1BERFactory_EMPTY_SET;

@implementation OrgSpongycastleAsn1BERFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1BERFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (OrgSpongycastleAsn1BERSequence *)createSequenceWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v {
  return OrgSpongycastleAsn1BERFactory_createSequenceWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (OrgSpongycastleAsn1BERSet *)createSetWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v {
  return OrgSpongycastleAsn1BERFactory_createSetWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1BERSequence;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1BERSet;", 0x8, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createSequenceWithOrgSpongycastleAsn1ASN1EncodableVector:);
  methods[2].selector = @selector(createSetWithOrgSpongycastleAsn1ASN1EncodableVector:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "EMPTY_SEQUENCE", "LOrgSpongycastleAsn1BERSequence;", .constantValue.asLong = 0, 0x18, -1, 3, -1, -1 },
    { "EMPTY_SET", "LOrgSpongycastleAsn1BERSet;", .constantValue.asLong = 0, 0x18, -1, 4, -1, -1 },
  };
  static const void *ptrTable[] = { "createSequence", "LOrgSpongycastleAsn1ASN1EncodableVector;", "createSet", &OrgSpongycastleAsn1BERFactory_EMPTY_SEQUENCE, &OrgSpongycastleAsn1BERFactory_EMPTY_SET };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1BERFactory = { "BERFactory", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x0, 3, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1BERFactory;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1BERFactory class]) {
    OrgSpongycastleAsn1BERFactory_EMPTY_SEQUENCE = new_OrgSpongycastleAsn1BERSequence_init();
    OrgSpongycastleAsn1BERFactory_EMPTY_SET = new_OrgSpongycastleAsn1BERSet_init();
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1BERFactory)
  }
}

@end

void OrgSpongycastleAsn1BERFactory_init(OrgSpongycastleAsn1BERFactory *self) {
  NSObject_init(self);
}

OrgSpongycastleAsn1BERFactory *new_OrgSpongycastleAsn1BERFactory_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BERFactory, init)
}

OrgSpongycastleAsn1BERFactory *create_OrgSpongycastleAsn1BERFactory_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BERFactory, init)
}

OrgSpongycastleAsn1BERSequence *OrgSpongycastleAsn1BERFactory_createSequenceWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *v) {
  OrgSpongycastleAsn1BERFactory_initialize();
  return [((OrgSpongycastleAsn1ASN1EncodableVector *) nil_chk(v)) size] < 1 ? OrgSpongycastleAsn1BERFactory_EMPTY_SEQUENCE : new_OrgSpongycastleAsn1BERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

OrgSpongycastleAsn1BERSet *OrgSpongycastleAsn1BERFactory_createSetWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *v) {
  OrgSpongycastleAsn1BERFactory_initialize();
  return [((OrgSpongycastleAsn1ASN1EncodableVector *) nil_chk(v)) size] < 1 ? OrgSpongycastleAsn1BERFactory_EMPTY_SET : new_OrgSpongycastleAsn1BERSet_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1BERFactory)