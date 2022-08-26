//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/CMPCertificate.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cmp/CMPCertificate.h"
#include "org/spongycastle/asn1/x509/AttributeCertificate.h"
#include "org/spongycastle/asn1/x509/Certificate.h"

@interface OrgSpongycastleAsn1CmpCMPCertificate () {
 @public
  OrgSpongycastleAsn1X509Certificate *x509v3PKCert_;
  jint otherTagValue_;
  OrgSpongycastleAsn1ASN1Object *otherCert_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpCMPCertificate, x509v3PKCert_, OrgSpongycastleAsn1X509Certificate *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpCMPCertificate, otherCert_, OrgSpongycastleAsn1ASN1Object *)

@implementation OrgSpongycastleAsn1CmpCMPCertificate

- (instancetype)initWithOrgSpongycastleAsn1X509AttributeCertificate:(OrgSpongycastleAsn1X509AttributeCertificate *)x509v2AttrCert {
  OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509AttributeCertificate_(self, x509v2AttrCert);
  return self;
}

- (instancetype)initWithInt:(jint)type
withOrgSpongycastleAsn1ASN1Object:(OrgSpongycastleAsn1ASN1Object *)otherCert {
  OrgSpongycastleAsn1CmpCMPCertificate_initWithInt_withOrgSpongycastleAsn1ASN1Object_(self, type, otherCert);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509Certificate:(OrgSpongycastleAsn1X509Certificate *)x509v3PKCert {
  OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509Certificate_(self, x509v3PKCert);
  return self;
}

+ (OrgSpongycastleAsn1CmpCMPCertificate *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmpCMPCertificate_getInstanceWithId_(o);
}

- (jboolean)isX509v3PKCert {
  return x509v3PKCert_ != nil;
}

- (OrgSpongycastleAsn1X509Certificate *)getX509v3PKCert {
  return x509v3PKCert_;
}

- (OrgSpongycastleAsn1X509AttributeCertificate *)getX509v2AttrCert {
  return OrgSpongycastleAsn1X509AttributeCertificate_getInstanceWithId_(otherCert_);
}

- (jint)getOtherCertTag {
  return otherTagValue_;
}

- (OrgSpongycastleAsn1ASN1Object *)getOtherCert {
  return otherCert_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (otherCert_ != nil) {
    return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, otherTagValue_, otherCert_);
  }
  return [((OrgSpongycastleAsn1X509Certificate *) nil_chk(x509v3PKCert_)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpCMPCertificate;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AttributeCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Object;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1X509AttributeCertificate:);
  methods[1].selector = @selector(initWithInt:withOrgSpongycastleAsn1ASN1Object:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509Certificate:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(isX509v3PKCert);
  methods[5].selector = @selector(getX509v3PKCert);
  methods[6].selector = @selector(getX509v2AttrCert);
  methods[7].selector = @selector(getOtherCertTag);
  methods[8].selector = @selector(getOtherCert);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x509v3PKCert_", "LOrgSpongycastleAsn1X509Certificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherTagValue_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherCert_", "LOrgSpongycastleAsn1ASN1Object;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1X509AttributeCertificate;", "ILOrgSpongycastleAsn1ASN1Object;", "LOrgSpongycastleAsn1X509Certificate;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmpCMPCertificate = { "CMPCertificate", "org.spongycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmpCMPCertificate;
}

@end

void OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509AttributeCertificate_(OrgSpongycastleAsn1CmpCMPCertificate *self, OrgSpongycastleAsn1X509AttributeCertificate *x509v2AttrCert) {
  OrgSpongycastleAsn1CmpCMPCertificate_initWithInt_withOrgSpongycastleAsn1ASN1Object_(self, 1, x509v2AttrCert);
}

OrgSpongycastleAsn1CmpCMPCertificate *new_OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509AttributeCertificate_(OrgSpongycastleAsn1X509AttributeCertificate *x509v2AttrCert) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCMPCertificate, initWithOrgSpongycastleAsn1X509AttributeCertificate_, x509v2AttrCert)
}

OrgSpongycastleAsn1CmpCMPCertificate *create_OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509AttributeCertificate_(OrgSpongycastleAsn1X509AttributeCertificate *x509v2AttrCert) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCMPCertificate, initWithOrgSpongycastleAsn1X509AttributeCertificate_, x509v2AttrCert)
}

void OrgSpongycastleAsn1CmpCMPCertificate_initWithInt_withOrgSpongycastleAsn1ASN1Object_(OrgSpongycastleAsn1CmpCMPCertificate *self, jint type, OrgSpongycastleAsn1ASN1Object *otherCert) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->otherTagValue_ = type;
  self->otherCert_ = otherCert;
}

OrgSpongycastleAsn1CmpCMPCertificate *new_OrgSpongycastleAsn1CmpCMPCertificate_initWithInt_withOrgSpongycastleAsn1ASN1Object_(jint type, OrgSpongycastleAsn1ASN1Object *otherCert) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCMPCertificate, initWithInt_withOrgSpongycastleAsn1ASN1Object_, type, otherCert)
}

OrgSpongycastleAsn1CmpCMPCertificate *create_OrgSpongycastleAsn1CmpCMPCertificate_initWithInt_withOrgSpongycastleAsn1ASN1Object_(jint type, OrgSpongycastleAsn1ASN1Object *otherCert) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCMPCertificate, initWithInt_withOrgSpongycastleAsn1ASN1Object_, type, otherCert)
}

void OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509Certificate_(OrgSpongycastleAsn1CmpCMPCertificate *self, OrgSpongycastleAsn1X509Certificate *x509v3PKCert) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1X509Certificate *) nil_chk(x509v3PKCert)) getVersionNumber] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"only version 3 certificates allowed");
  }
  self->x509v3PKCert_ = x509v3PKCert;
}

OrgSpongycastleAsn1CmpCMPCertificate *new_OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509Certificate_(OrgSpongycastleAsn1X509Certificate *x509v3PKCert) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCMPCertificate, initWithOrgSpongycastleAsn1X509Certificate_, x509v3PKCert)
}

OrgSpongycastleAsn1CmpCMPCertificate *create_OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509Certificate_(OrgSpongycastleAsn1X509Certificate *x509v3PKCert) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCMPCertificate, initWithOrgSpongycastleAsn1X509Certificate_, x509v3PKCert)
}

OrgSpongycastleAsn1CmpCMPCertificate *OrgSpongycastleAsn1CmpCMPCertificate_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmpCMPCertificate_initialize();
  if (o == nil || [o isKindOfClass:[OrgSpongycastleAsn1CmpCMPCertificate class]]) {
    return (OrgSpongycastleAsn1CmpCMPCertificate *) cast_chk(o, [OrgSpongycastleAsn1CmpCMPCertificate class]);
  }
  if ([o isKindOfClass:[IOSByteArray class]]) {
    @try {
      o = OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(o, [IOSByteArray class]));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid encoding in CMPCertificate");
    }
  }
  if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1CmpCMPCertificate_initWithOrgSpongycastleAsn1X509Certificate_(OrgSpongycastleAsn1X509Certificate_getInstanceWithId_(o));
  }
  if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    OrgSpongycastleAsn1ASN1TaggedObject *taggedObject = (OrgSpongycastleAsn1ASN1TaggedObject *) o;
    return new_OrgSpongycastleAsn1CmpCMPCertificate_initWithInt_withOrgSpongycastleAsn1ASN1Object_([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(taggedObject)) getTagNo], [taggedObject getObject]);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid object: ", [[nil_chk(o) java_getClass] getName]));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmpCMPCertificate)
