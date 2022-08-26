//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/GetCert.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cmc/GetCert.h"
#include "org/spongycastle/asn1/x509/GeneralName.h"

@interface OrgSpongycastleAsn1CmcGetCert () {
 @public
  OrgSpongycastleAsn1X509GeneralName *issuerName_;
  JavaMathBigInteger *serialNumber_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcGetCert, issuerName_, OrgSpongycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcGetCert, serialNumber_, JavaMathBigInteger *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcGetCert *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmcGetCert *new_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmcGetCert *create_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmcGetCert

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)issuerName
                                    withJavaMathBigInteger:(JavaMathBigInteger *)serialNumber {
  OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1X509GeneralName_withJavaMathBigInteger_(self, issuerName, serialNumber);
  return self;
}

+ (OrgSpongycastleAsn1CmcGetCert *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmcGetCert_getInstanceWithId_(o);
}

- (OrgSpongycastleAsn1X509GeneralName *)getIssuerName {
  return issuerName_;
}

- (JavaMathBigInteger *)getSerialNumber {
  return serialNumber_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:issuerName_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(serialNumber_)];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcGetCert;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralName:withJavaMathBigInteger:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getIssuerName);
  methods[4].selector = @selector(getSerialNumber);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "issuerName_", "LOrgSpongycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "serialNumber_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1X509GeneralName;LJavaMathBigInteger;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcGetCert = { "GetCert", "org.spongycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcGetCert;
}

@end

void OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcGetCert *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->issuerName_ = OrgSpongycastleAsn1X509GeneralName_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->serialNumber_ = [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:1]))) getValue];
}

OrgSpongycastleAsn1CmcGetCert *new_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcGetCert, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcGetCert *create_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcGetCert, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1X509GeneralName_withJavaMathBigInteger_(OrgSpongycastleAsn1CmcGetCert *self, OrgSpongycastleAsn1X509GeneralName *issuerName, JavaMathBigInteger *serialNumber) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->issuerName_ = issuerName;
  self->serialNumber_ = serialNumber;
}

OrgSpongycastleAsn1CmcGetCert *new_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1X509GeneralName_withJavaMathBigInteger_(OrgSpongycastleAsn1X509GeneralName *issuerName, JavaMathBigInteger *serialNumber) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcGetCert, initWithOrgSpongycastleAsn1X509GeneralName_withJavaMathBigInteger_, issuerName, serialNumber)
}

OrgSpongycastleAsn1CmcGetCert *create_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1X509GeneralName_withJavaMathBigInteger_(OrgSpongycastleAsn1X509GeneralName *issuerName, JavaMathBigInteger *serialNumber) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcGetCert, initWithOrgSpongycastleAsn1X509GeneralName_withJavaMathBigInteger_, issuerName, serialNumber)
}

OrgSpongycastleAsn1CmcGetCert *OrgSpongycastleAsn1CmcGetCert_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmcGetCert_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmcGetCert class]]) {
    return (OrgSpongycastleAsn1CmcGetCert *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmcGetCert_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcGetCert)