//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/X509Extension.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Boolean.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/x509/X509Extension.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1X509X509Extension)

OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_subjectDirectoryAttributes;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_subjectKeyIdentifier;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_keyUsage;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_privateKeyUsagePeriod;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_subjectAlternativeName;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_issuerAlternativeName;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_basicConstraints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_cRLNumber;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_reasonCode;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_instructionCode;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_invalidityDate;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_deltaCRLIndicator;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_issuingDistributionPoint;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_certificateIssuer;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_nameConstraints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_cRLDistributionPoints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_certificatePolicies;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_policyMappings;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_authorityKeyIdentifier;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_policyConstraints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_extendedKeyUsage;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_freshestCRL;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_inhibitAnyPolicy;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_authorityInfoAccess;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_subjectInfoAccess;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_logoType;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_biometricInfo;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_qCStatements;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_auditIdentity;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_noRevAvail;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509X509Extension_targetInformation;

@implementation OrgSpongycastleAsn1X509X509Extension

- (instancetype)initWithOrgSpongycastleAsn1ASN1Boolean:(OrgSpongycastleAsn1ASN1Boolean *)critical
                withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)value {
  OrgSpongycastleAsn1X509X509Extension_initWithOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(self, critical, value);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)critical
withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)value {
  OrgSpongycastleAsn1X509X509Extension_initWithBoolean_withOrgSpongycastleAsn1ASN1OctetString_(self, critical, value);
  return self;
}

- (jboolean)isCritical {
  return critical_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getValue {
  return value_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getParsedValue {
  return OrgSpongycastleAsn1X509X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509X509Extension_(self);
}

- (NSUInteger)hash {
  if ([self isCritical]) {
    return ((jint) [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([self getValue])) hash]);
  }
  return ~((jint) [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([self getValue])) hash]);
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1X509X509Extension class]])) {
    return false;
  }
  OrgSpongycastleAsn1X509X509Extension *other = (OrgSpongycastleAsn1X509X509Extension *) cast_chk(o, [OrgSpongycastleAsn1X509X509Extension class]);
  return [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([((OrgSpongycastleAsn1X509X509Extension *) nil_chk(other)) getValue])) isEqual:[self getValue]] && ([other isCritical] == [self isCritical]);
}

+ (OrgSpongycastleAsn1ASN1Primitive *)convertValueToObjectWithOrgSpongycastleAsn1X509X509Extension:(OrgSpongycastleAsn1X509X509Extension *)ext {
  return OrgSpongycastleAsn1X509X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509X509Extension_(ext);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x9, 5, 6, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Boolean:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(initWithBoolean:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[2].selector = @selector(isCritical);
  methods[3].selector = @selector(getValue);
  methods[4].selector = @selector(getParsedValue);
  methods[5].selector = @selector(hash);
  methods[6].selector = @selector(isEqual:);
  methods[7].selector = @selector(convertValueToObjectWithOrgSpongycastleAsn1X509X509Extension:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "subjectDirectoryAttributes", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 8, -1, -1 },
    { "subjectKeyIdentifier", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
    { "keyUsage", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
    { "privateKeyUsagePeriod", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 11, -1, -1 },
    { "subjectAlternativeName", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 12, -1, -1 },
    { "issuerAlternativeName", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 13, -1, -1 },
    { "basicConstraints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 14, -1, -1 },
    { "cRLNumber", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "reasonCode", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "instructionCode", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
    { "invalidityDate", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "deltaCRLIndicator", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 19, -1, -1 },
    { "issuingDistributionPoint", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 20, -1, -1 },
    { "certificateIssuer", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "nameConstraints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "cRLDistributionPoints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 23, -1, -1 },
    { "certificatePolicies", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 24, -1, -1 },
    { "policyMappings", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 25, -1, -1 },
    { "authorityKeyIdentifier", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 26, -1, -1 },
    { "policyConstraints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 27, -1, -1 },
    { "extendedKeyUsage", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 28, -1, -1 },
    { "freshestCRL", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 29, -1, -1 },
    { "inhibitAnyPolicy", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 30, -1, -1 },
    { "authorityInfoAccess", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 31, -1, -1 },
    { "subjectInfoAccess", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 32, -1, -1 },
    { "logoType", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 33, -1, -1 },
    { "biometricInfo", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 34, -1, -1 },
    { "qCStatements", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 35, -1, -1 },
    { "auditIdentity", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 36, -1, -1 },
    { "noRevAvail", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 37, -1, -1 },
    { "targetInformation", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 38, -1, -1 },
    { "critical_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "value_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Boolean;LOrgSpongycastleAsn1ASN1OctetString;", "ZLOrgSpongycastleAsn1ASN1OctetString;", "hashCode", "equals", "LNSObject;", "convertValueToObject", "LOrgSpongycastleAsn1X509X509Extension;", "LJavaLangIllegalArgumentException;", &OrgSpongycastleAsn1X509X509Extension_subjectDirectoryAttributes, &OrgSpongycastleAsn1X509X509Extension_subjectKeyIdentifier, &OrgSpongycastleAsn1X509X509Extension_keyUsage, &OrgSpongycastleAsn1X509X509Extension_privateKeyUsagePeriod, &OrgSpongycastleAsn1X509X509Extension_subjectAlternativeName, &OrgSpongycastleAsn1X509X509Extension_issuerAlternativeName, &OrgSpongycastleAsn1X509X509Extension_basicConstraints, &OrgSpongycastleAsn1X509X509Extension_cRLNumber, &OrgSpongycastleAsn1X509X509Extension_reasonCode, &OrgSpongycastleAsn1X509X509Extension_instructionCode, &OrgSpongycastleAsn1X509X509Extension_invalidityDate, &OrgSpongycastleAsn1X509X509Extension_deltaCRLIndicator, &OrgSpongycastleAsn1X509X509Extension_issuingDistributionPoint, &OrgSpongycastleAsn1X509X509Extension_certificateIssuer, &OrgSpongycastleAsn1X509X509Extension_nameConstraints, &OrgSpongycastleAsn1X509X509Extension_cRLDistributionPoints, &OrgSpongycastleAsn1X509X509Extension_certificatePolicies, &OrgSpongycastleAsn1X509X509Extension_policyMappings, &OrgSpongycastleAsn1X509X509Extension_authorityKeyIdentifier, &OrgSpongycastleAsn1X509X509Extension_policyConstraints, &OrgSpongycastleAsn1X509X509Extension_extendedKeyUsage, &OrgSpongycastleAsn1X509X509Extension_freshestCRL, &OrgSpongycastleAsn1X509X509Extension_inhibitAnyPolicy, &OrgSpongycastleAsn1X509X509Extension_authorityInfoAccess, &OrgSpongycastleAsn1X509X509Extension_subjectInfoAccess, &OrgSpongycastleAsn1X509X509Extension_logoType, &OrgSpongycastleAsn1X509X509Extension_biometricInfo, &OrgSpongycastleAsn1X509X509Extension_qCStatements, &OrgSpongycastleAsn1X509X509Extension_auditIdentity, &OrgSpongycastleAsn1X509X509Extension_noRevAvail, &OrgSpongycastleAsn1X509X509Extension_targetInformation };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509X509Extension = { "X509Extension", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 8, 33, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509X509Extension;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1X509X509Extension class]) {
    OrgSpongycastleAsn1X509X509Extension_subjectDirectoryAttributes = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.9");
    OrgSpongycastleAsn1X509X509Extension_subjectKeyIdentifier = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.14");
    OrgSpongycastleAsn1X509X509Extension_keyUsage = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.15");
    OrgSpongycastleAsn1X509X509Extension_privateKeyUsagePeriod = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.16");
    OrgSpongycastleAsn1X509X509Extension_subjectAlternativeName = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.17");
    OrgSpongycastleAsn1X509X509Extension_issuerAlternativeName = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.18");
    OrgSpongycastleAsn1X509X509Extension_basicConstraints = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.19");
    OrgSpongycastleAsn1X509X509Extension_cRLNumber = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.20");
    OrgSpongycastleAsn1X509X509Extension_reasonCode = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.21");
    OrgSpongycastleAsn1X509X509Extension_instructionCode = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.23");
    OrgSpongycastleAsn1X509X509Extension_invalidityDate = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.24");
    OrgSpongycastleAsn1X509X509Extension_deltaCRLIndicator = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.27");
    OrgSpongycastleAsn1X509X509Extension_issuingDistributionPoint = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.28");
    OrgSpongycastleAsn1X509X509Extension_certificateIssuer = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.29");
    OrgSpongycastleAsn1X509X509Extension_nameConstraints = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.30");
    OrgSpongycastleAsn1X509X509Extension_cRLDistributionPoints = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.31");
    OrgSpongycastleAsn1X509X509Extension_certificatePolicies = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.32");
    OrgSpongycastleAsn1X509X509Extension_policyMappings = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.33");
    OrgSpongycastleAsn1X509X509Extension_authorityKeyIdentifier = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.35");
    OrgSpongycastleAsn1X509X509Extension_policyConstraints = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.36");
    OrgSpongycastleAsn1X509X509Extension_extendedKeyUsage = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.37");
    OrgSpongycastleAsn1X509X509Extension_freshestCRL = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.46");
    OrgSpongycastleAsn1X509X509Extension_inhibitAnyPolicy = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.54");
    OrgSpongycastleAsn1X509X509Extension_authorityInfoAccess = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.1");
    OrgSpongycastleAsn1X509X509Extension_subjectInfoAccess = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.11");
    OrgSpongycastleAsn1X509X509Extension_logoType = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.12");
    OrgSpongycastleAsn1X509X509Extension_biometricInfo = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.2");
    OrgSpongycastleAsn1X509X509Extension_qCStatements = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.3");
    OrgSpongycastleAsn1X509X509Extension_auditIdentity = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.4");
    OrgSpongycastleAsn1X509X509Extension_noRevAvail = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.56");
    OrgSpongycastleAsn1X509X509Extension_targetInformation = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.55");
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1X509X509Extension)
  }
}

@end

void OrgSpongycastleAsn1X509X509Extension_initWithOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509X509Extension *self, OrgSpongycastleAsn1ASN1Boolean *critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  NSObject_init(self);
  self->critical_ = [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(critical)) isTrue];
  self->value_ = value;
}

OrgSpongycastleAsn1X509X509Extension *new_OrgSpongycastleAsn1X509X509Extension_initWithOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1Boolean *critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509X509Extension, initWithOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_, critical, value)
}

OrgSpongycastleAsn1X509X509Extension *create_OrgSpongycastleAsn1X509X509Extension_initWithOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1Boolean *critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509X509Extension, initWithOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_, critical, value)
}

void OrgSpongycastleAsn1X509X509Extension_initWithBoolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509X509Extension *self, jboolean critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  NSObject_init(self);
  self->critical_ = critical;
  self->value_ = value;
}

OrgSpongycastleAsn1X509X509Extension *new_OrgSpongycastleAsn1X509X509Extension_initWithBoolean_withOrgSpongycastleAsn1ASN1OctetString_(jboolean critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509X509Extension, initWithBoolean_withOrgSpongycastleAsn1ASN1OctetString_, critical, value)
}

OrgSpongycastleAsn1X509X509Extension *create_OrgSpongycastleAsn1X509X509Extension_initWithBoolean_withOrgSpongycastleAsn1ASN1OctetString_(jboolean critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509X509Extension, initWithBoolean_withOrgSpongycastleAsn1ASN1OctetString_, critical, value)
}

OrgSpongycastleAsn1ASN1Primitive *OrgSpongycastleAsn1X509X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509X509Extension_(OrgSpongycastleAsn1X509X509Extension *ext) {
  OrgSpongycastleAsn1X509X509Extension_initialize();
  @try {
    return OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([((OrgSpongycastleAsn1X509X509Extension *) nil_chk(ext)) getValue])) getOctets]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"can't convert extension: ", e));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509X509Extension)
