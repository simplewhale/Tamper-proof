//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ess/ContentIdentifier.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/ess/ContentIdentifier.h"

@interface OrgSpongycastleAsn1EssContentIdentifier ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)value;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1EssContentIdentifier *self, OrgSpongycastleAsn1ASN1OctetString *value);

__attribute__((unused)) static OrgSpongycastleAsn1EssContentIdentifier *new_OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *value) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1EssContentIdentifier *create_OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *value);

@implementation OrgSpongycastleAsn1EssContentIdentifier

+ (OrgSpongycastleAsn1EssContentIdentifier *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1EssContentIdentifier_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)value {
  OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(self, value);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)value {
  OrgSpongycastleAsn1EssContentIdentifier_initWithByteArray_(self, value);
  return self;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getValue {
  return value_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return value_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1EssContentIdentifier;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1OctetString:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(getValue);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "value_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1OctetString;", "[B" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1EssContentIdentifier = { "ContentIdentifier", "org.spongycastle.asn1.ess", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1EssContentIdentifier;
}

@end

OrgSpongycastleAsn1EssContentIdentifier *OrgSpongycastleAsn1EssContentIdentifier_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1EssContentIdentifier_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1EssContentIdentifier class]]) {
    return (OrgSpongycastleAsn1EssContentIdentifier *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1EssContentIdentifier *self, OrgSpongycastleAsn1ASN1OctetString *value) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->value_ = value;
}

OrgSpongycastleAsn1EssContentIdentifier *new_OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EssContentIdentifier, initWithOrgSpongycastleAsn1ASN1OctetString_, value)
}

OrgSpongycastleAsn1EssContentIdentifier *create_OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EssContentIdentifier, initWithOrgSpongycastleAsn1ASN1OctetString_, value)
}

void OrgSpongycastleAsn1EssContentIdentifier_initWithByteArray_(OrgSpongycastleAsn1EssContentIdentifier *self, IOSByteArray *value) {
  OrgSpongycastleAsn1EssContentIdentifier_initWithOrgSpongycastleAsn1ASN1OctetString_(self, new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(value));
}

OrgSpongycastleAsn1EssContentIdentifier *new_OrgSpongycastleAsn1EssContentIdentifier_initWithByteArray_(IOSByteArray *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EssContentIdentifier, initWithByteArray_, value)
}

OrgSpongycastleAsn1EssContentIdentifier *create_OrgSpongycastleAsn1EssContentIdentifier_initWithByteArray_(IOSByteArray *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EssContentIdentifier, initWithByteArray_, value)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1EssContentIdentifier)
