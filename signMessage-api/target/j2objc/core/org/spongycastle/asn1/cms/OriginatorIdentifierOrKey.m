//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/OriginatorIdentifierOrKey.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cms/IssuerAndSerialNumber.h"
#include "org/spongycastle/asn1/cms/OriginatorIdentifierOrKey.h"
#include "org/spongycastle/asn1/cms/OriginatorPublicKey.h"
#include "org/spongycastle/asn1/x509/SubjectKeyIdentifier.h"

@interface OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey () {
 @public
  id<OrgSpongycastleAsn1ASN1Encodable> id__;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, id__, id<OrgSpongycastleAsn1ASN1Encodable>)

@implementation OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey

- (instancetype)initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber:(OrgSpongycastleAsn1CmsIssuerAndSerialNumber *)id_ {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_(self, id_);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)id_ {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1OctetString_(self, id_);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier:(OrgSpongycastleAsn1X509SubjectKeyIdentifier *)id_ {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_(self, id_);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1CmsOriginatorPublicKey:(OrgSpongycastleAsn1CmsOriginatorPublicKey *)id_ {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_(self, id_);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)id_ {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1Primitive_(self, id_);
  return self;
}

+ (OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)o
                                                                                            withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, explicit_);
}

+ (OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_getInstanceWithId_(o);
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getId {
  return id__;
}

- (OrgSpongycastleAsn1CmsIssuerAndSerialNumber *)getIssuerAndSerialNumber {
  if ([id__ isKindOfClass:[OrgSpongycastleAsn1CmsIssuerAndSerialNumber class]]) {
    return (OrgSpongycastleAsn1CmsIssuerAndSerialNumber *) id__;
  }
  return nil;
}

- (OrgSpongycastleAsn1X509SubjectKeyIdentifier *)getSubjectKeyIdentifier {
  if ([id__ isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]] && [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk(id__, [OrgSpongycastleAsn1ASN1TaggedObject class])))) getTagNo] == 0) {
    return OrgSpongycastleAsn1X509SubjectKeyIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk(id__, [OrgSpongycastleAsn1ASN1TaggedObject class]), false);
  }
  return nil;
}

- (OrgSpongycastleAsn1CmsOriginatorPublicKey *)getOriginatorKey {
  if ([id__ isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]] && [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk(id__, [OrgSpongycastleAsn1ASN1TaggedObject class])))) getTagNo] == 1) {
    return OrgSpongycastleAsn1CmsOriginatorPublicKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk(id__, [OrgSpongycastleAsn1ASN1TaggedObject class]), false);
  }
  return nil;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk(id__)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsOriginatorIdentifierOrKey;", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsOriginatorIdentifierOrKey;", 0x9, 5, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsIssuerAndSerialNumber;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509SubjectKeyIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsOriginatorPublicKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1OctetString:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1CmsOriginatorPublicKey:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[5].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[6].selector = @selector(getInstanceWithId:);
  methods[7].selector = @selector(getId);
  methods[8].selector = @selector(getIssuerAndSerialNumber);
  methods[9].selector = @selector(getSubjectKeyIdentifier);
  methods[10].selector = @selector(getOriginatorKey);
  methods[11].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "id__", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, 8, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1CmsIssuerAndSerialNumber;", "LOrgSpongycastleAsn1ASN1OctetString;", "LOrgSpongycastleAsn1X509SubjectKeyIdentifier;", "LOrgSpongycastleAsn1CmsOriginatorPublicKey;", "LOrgSpongycastleAsn1ASN1Primitive;", "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "id" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey = { "OriginatorIdentifierOrKey", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 12, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey;
}

@end

void OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *self, OrgSpongycastleAsn1CmsIssuerAndSerialNumber *id_) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->id__ = id_;
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_(OrgSpongycastleAsn1CmsIssuerAndSerialNumber *id_) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_, id_)
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *create_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_(OrgSpongycastleAsn1CmsIssuerAndSerialNumber *id_) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_, id_)
}

void OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *self, OrgSpongycastleAsn1ASN1OctetString *id_) {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_(self, new_OrgSpongycastleAsn1X509SubjectKeyIdentifier_initWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(id_)) getOctets]));
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *id_) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1ASN1OctetString_, id_)
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *create_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *id_) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1ASN1OctetString_, id_)
}

void OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *self, OrgSpongycastleAsn1X509SubjectKeyIdentifier *id_) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->id__ = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, id_);
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_(OrgSpongycastleAsn1X509SubjectKeyIdentifier *id_) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_, id_)
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *create_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_(OrgSpongycastleAsn1X509SubjectKeyIdentifier *id_) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_, id_)
}

void OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *self, OrgSpongycastleAsn1CmsOriginatorPublicKey *id_) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->id__ = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, id_);
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_(OrgSpongycastleAsn1CmsOriginatorPublicKey *id_) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_, id_)
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *create_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_(OrgSpongycastleAsn1CmsOriginatorPublicKey *id_) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_, id_)
}

void OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *self, OrgSpongycastleAsn1ASN1Primitive *id_) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->id__ = id_;
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *id_) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1ASN1Primitive_, id_)
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *create_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *id_) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey, initWithOrgSpongycastleAsn1ASN1Primitive_, id_)
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *o, jboolean explicit_) {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initialize();
  if (!explicit_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Can't implicitly tag OriginatorIdentifierOrKey");
  }
  return OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_getInstanceWithId_([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getObject]);
}

OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initialize();
  if (o == nil || [o isKindOfClass:[OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey class]]) {
    return (OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey *) cast_chk(o, [OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey class]);
  }
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmsIssuerAndSerialNumber class]] || [o isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsIssuerAndSerialNumber_(OrgSpongycastleAsn1CmsIssuerAndSerialNumber_getInstanceWithId_(o));
  }
  if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    OrgSpongycastleAsn1ASN1TaggedObject *tagged = (OrgSpongycastleAsn1ASN1TaggedObject *) o;
    if ([tagged getTagNo] == 0) {
      return new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1X509SubjectKeyIdentifier_(OrgSpongycastleAsn1X509SubjectKeyIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false));
    }
    else if ([tagged getTagNo] == 1) {
      return new_OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey_initWithOrgSpongycastleAsn1CmsOriginatorPublicKey_(OrgSpongycastleAsn1CmsOriginatorPublicKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid OriginatorIdentifierOrKey: ", [[o java_getClass] getName]));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsOriginatorIdentifierOrKey)
