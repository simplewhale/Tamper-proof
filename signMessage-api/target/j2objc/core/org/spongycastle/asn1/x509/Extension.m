//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/Extension.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Boolean.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x509/Extension.h"

@interface OrgSpongycastleAsn1X509Extension () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId_;
  jboolean critical_;
  OrgSpongycastleAsn1ASN1OctetString *value_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

+ (OrgSpongycastleAsn1ASN1Primitive *)convertValueToObjectWithOrgSpongycastleAsn1X509Extension:(OrgSpongycastleAsn1X509Extension *)ext;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509Extension, extnId_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509Extension, value_, OrgSpongycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509Extension *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509Extension *new_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509Extension *create_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1ASN1Primitive *OrgSpongycastleAsn1X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509Extension_(OrgSpongycastleAsn1X509Extension *ext);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1X509Extension)

OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_subjectDirectoryAttributes;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_subjectKeyIdentifier;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_keyUsage;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_privateKeyUsagePeriod;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_subjectAlternativeName;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_issuerAlternativeName;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_basicConstraints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_cRLNumber;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_reasonCode;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_instructionCode;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_invalidityDate;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_deltaCRLIndicator;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_issuingDistributionPoint;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_certificateIssuer;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_nameConstraints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_cRLDistributionPoints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_certificatePolicies;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_policyMappings;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_authorityKeyIdentifier;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_policyConstraints;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_extendedKeyUsage;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_freshestCRL;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_inhibitAnyPolicy;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_authorityInfoAccess;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_subjectInfoAccess;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_logoType;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_biometricInfo;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_qCStatements;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_auditIdentity;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_noRevAvail;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_targetInformation;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1X509Extension_expiredCertsOnCRL;

@implementation OrgSpongycastleAsn1X509Extension

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)extnId
                             withOrgSpongycastleAsn1ASN1Boolean:(OrgSpongycastleAsn1ASN1Boolean *)critical
                         withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)value {
  OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(self, extnId, critical, value);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)extnId
                                                    withBoolean:(jboolean)critical
                                                  withByteArray:(IOSByteArray *)value {
  OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(self, extnId, critical, value);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)extnId
                                                    withBoolean:(jboolean)critical
                         withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)value {
  OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_(self, extnId, critical, value);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1X509Extension *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509Extension_getInstanceWithId_(obj);
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getExtnId {
  return extnId_;
}

- (jboolean)isCritical {
  return critical_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getExtnValue {
  return value_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getParsedValue {
  return OrgSpongycastleAsn1X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509Extension_(self);
}

- (NSUInteger)hash {
  if ([self isCritical]) {
    return ((jint) [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([self getExtnValue])) hash]) ^ ((jint) [((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([self getExtnId])) hash]);
  }
  return ~(((jint) [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([self getExtnValue])) hash]) ^ ((jint) [((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([self getExtnId])) hash]));
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1X509Extension class]])) {
    return false;
  }
  OrgSpongycastleAsn1X509Extension *other = (OrgSpongycastleAsn1X509Extension *) cast_chk(o, [OrgSpongycastleAsn1X509Extension class]);
  return [((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([((OrgSpongycastleAsn1X509Extension *) nil_chk(other)) getExtnId])) isEqual:[self getExtnId]] && [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([other getExtnValue])) isEqual:[self getExtnValue]] && ([other isCritical] == [self isCritical]);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:extnId_];
  if (critical_) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(true)];
  }
  [v addWithOrgSpongycastleAsn1ASN1Encodable:value_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (OrgSpongycastleAsn1ASN1Primitive *)convertValueToObjectWithOrgSpongycastleAsn1X509Extension:(OrgSpongycastleAsn1X509Extension *)ext {
  return OrgSpongycastleAsn1X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509Extension_(ext);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Extension;", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 7, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0xa, 8, 9, 10, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Boolean:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withBoolean:withByteArray:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withBoolean:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getExtnId);
  methods[6].selector = @selector(isCritical);
  methods[7].selector = @selector(getExtnValue);
  methods[8].selector = @selector(getParsedValue);
  methods[9].selector = @selector(hash);
  methods[10].selector = @selector(isEqual:);
  methods[11].selector = @selector(toASN1Primitive);
  methods[12].selector = @selector(convertValueToObjectWithOrgSpongycastleAsn1X509Extension:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "subjectDirectoryAttributes", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 11, -1, -1 },
    { "subjectKeyIdentifier", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 12, -1, -1 },
    { "keyUsage", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 13, -1, -1 },
    { "privateKeyUsagePeriod", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 14, -1, -1 },
    { "subjectAlternativeName", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "issuerAlternativeName", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "basicConstraints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
    { "cRLNumber", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "reasonCode", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 19, -1, -1 },
    { "instructionCode", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 20, -1, -1 },
    { "invalidityDate", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "deltaCRLIndicator", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "issuingDistributionPoint", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 23, -1, -1 },
    { "certificateIssuer", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 24, -1, -1 },
    { "nameConstraints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 25, -1, -1 },
    { "cRLDistributionPoints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 26, -1, -1 },
    { "certificatePolicies", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 27, -1, -1 },
    { "policyMappings", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 28, -1, -1 },
    { "authorityKeyIdentifier", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 29, -1, -1 },
    { "policyConstraints", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 30, -1, -1 },
    { "extendedKeyUsage", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 31, -1, -1 },
    { "freshestCRL", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 32, -1, -1 },
    { "inhibitAnyPolicy", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 33, -1, -1 },
    { "authorityInfoAccess", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 34, -1, -1 },
    { "subjectInfoAccess", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 35, -1, -1 },
    { "logoType", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 36, -1, -1 },
    { "biometricInfo", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 37, -1, -1 },
    { "qCStatements", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 38, -1, -1 },
    { "auditIdentity", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 39, -1, -1 },
    { "noRevAvail", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 40, -1, -1 },
    { "targetInformation", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 41, -1, -1 },
    { "expiredCertsOnCRL", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 42, -1, -1 },
    { "extnId_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "critical_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "value_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Boolean;LOrgSpongycastleAsn1ASN1OctetString;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;Z[B", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;ZLOrgSpongycastleAsn1ASN1OctetString;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "hashCode", "equals", "convertValueToObject", "LOrgSpongycastleAsn1X509Extension;", "LJavaLangIllegalArgumentException;", &OrgSpongycastleAsn1X509Extension_subjectDirectoryAttributes, &OrgSpongycastleAsn1X509Extension_subjectKeyIdentifier, &OrgSpongycastleAsn1X509Extension_keyUsage, &OrgSpongycastleAsn1X509Extension_privateKeyUsagePeriod, &OrgSpongycastleAsn1X509Extension_subjectAlternativeName, &OrgSpongycastleAsn1X509Extension_issuerAlternativeName, &OrgSpongycastleAsn1X509Extension_basicConstraints, &OrgSpongycastleAsn1X509Extension_cRLNumber, &OrgSpongycastleAsn1X509Extension_reasonCode, &OrgSpongycastleAsn1X509Extension_instructionCode, &OrgSpongycastleAsn1X509Extension_invalidityDate, &OrgSpongycastleAsn1X509Extension_deltaCRLIndicator, &OrgSpongycastleAsn1X509Extension_issuingDistributionPoint, &OrgSpongycastleAsn1X509Extension_certificateIssuer, &OrgSpongycastleAsn1X509Extension_nameConstraints, &OrgSpongycastleAsn1X509Extension_cRLDistributionPoints, &OrgSpongycastleAsn1X509Extension_certificatePolicies, &OrgSpongycastleAsn1X509Extension_policyMappings, &OrgSpongycastleAsn1X509Extension_authorityKeyIdentifier, &OrgSpongycastleAsn1X509Extension_policyConstraints, &OrgSpongycastleAsn1X509Extension_extendedKeyUsage, &OrgSpongycastleAsn1X509Extension_freshestCRL, &OrgSpongycastleAsn1X509Extension_inhibitAnyPolicy, &OrgSpongycastleAsn1X509Extension_authorityInfoAccess, &OrgSpongycastleAsn1X509Extension_subjectInfoAccess, &OrgSpongycastleAsn1X509Extension_logoType, &OrgSpongycastleAsn1X509Extension_biometricInfo, &OrgSpongycastleAsn1X509Extension_qCStatements, &OrgSpongycastleAsn1X509Extension_auditIdentity, &OrgSpongycastleAsn1X509Extension_noRevAvail, &OrgSpongycastleAsn1X509Extension_targetInformation, &OrgSpongycastleAsn1X509Extension_expiredCertsOnCRL };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509Extension = { "Extension", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 13, 35, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509Extension;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1X509Extension class]) {
    OrgSpongycastleAsn1X509Extension_subjectDirectoryAttributes = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.9") intern];
    OrgSpongycastleAsn1X509Extension_subjectKeyIdentifier = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.14") intern];
    OrgSpongycastleAsn1X509Extension_keyUsage = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.15") intern];
    OrgSpongycastleAsn1X509Extension_privateKeyUsagePeriod = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.16") intern];
    OrgSpongycastleAsn1X509Extension_subjectAlternativeName = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.17") intern];
    OrgSpongycastleAsn1X509Extension_issuerAlternativeName = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.18") intern];
    OrgSpongycastleAsn1X509Extension_basicConstraints = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.19") intern];
    OrgSpongycastleAsn1X509Extension_cRLNumber = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.20") intern];
    OrgSpongycastleAsn1X509Extension_reasonCode = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.21") intern];
    OrgSpongycastleAsn1X509Extension_instructionCode = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.23") intern];
    OrgSpongycastleAsn1X509Extension_invalidityDate = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.24") intern];
    OrgSpongycastleAsn1X509Extension_deltaCRLIndicator = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.27") intern];
    OrgSpongycastleAsn1X509Extension_issuingDistributionPoint = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.28") intern];
    OrgSpongycastleAsn1X509Extension_certificateIssuer = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.29") intern];
    OrgSpongycastleAsn1X509Extension_nameConstraints = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.30") intern];
    OrgSpongycastleAsn1X509Extension_cRLDistributionPoints = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.31") intern];
    OrgSpongycastleAsn1X509Extension_certificatePolicies = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.32") intern];
    OrgSpongycastleAsn1X509Extension_policyMappings = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.33") intern];
    OrgSpongycastleAsn1X509Extension_authorityKeyIdentifier = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.35") intern];
    OrgSpongycastleAsn1X509Extension_policyConstraints = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.36") intern];
    OrgSpongycastleAsn1X509Extension_extendedKeyUsage = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.37") intern];
    OrgSpongycastleAsn1X509Extension_freshestCRL = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.46") intern];
    OrgSpongycastleAsn1X509Extension_inhibitAnyPolicy = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.54") intern];
    OrgSpongycastleAsn1X509Extension_authorityInfoAccess = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.1") intern];
    OrgSpongycastleAsn1X509Extension_subjectInfoAccess = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.11") intern];
    OrgSpongycastleAsn1X509Extension_logoType = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.12") intern];
    OrgSpongycastleAsn1X509Extension_biometricInfo = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.2") intern];
    OrgSpongycastleAsn1X509Extension_qCStatements = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.3") intern];
    OrgSpongycastleAsn1X509Extension_auditIdentity = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.4") intern];
    OrgSpongycastleAsn1X509Extension_noRevAvail = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.56") intern];
    OrgSpongycastleAsn1X509Extension_targetInformation = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.55") intern];
    OrgSpongycastleAsn1X509Extension_expiredCertsOnCRL = [new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.60") intern];
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1X509Extension)
  }
}

@end

void OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509Extension *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, OrgSpongycastleAsn1ASN1Boolean *critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_(self, extnId, [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(critical)) isTrue], value);
}

OrgSpongycastleAsn1X509Extension *new_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, OrgSpongycastleAsn1ASN1Boolean *critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_, extnId, critical, value)
}

OrgSpongycastleAsn1X509Extension *create_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, OrgSpongycastleAsn1ASN1Boolean *critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1ASN1OctetString_, extnId, critical, value)
}

void OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(OrgSpongycastleAsn1X509Extension *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) {
  OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_(self, extnId, critical, new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(value));
}

OrgSpongycastleAsn1X509Extension *new_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_, extnId, critical, value)
}

OrgSpongycastleAsn1X509Extension *create_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_, extnId, critical, value)
}

void OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509Extension *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->extnId_ = extnId;
  self->critical_ = critical;
  self->value_ = value;
}

OrgSpongycastleAsn1X509Extension *new_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_, extnId, critical, value)
}

OrgSpongycastleAsn1X509Extension *create_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, OrgSpongycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withOrgSpongycastleAsn1ASN1OctetString_, extnId, critical, value)
}

void OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509Extension *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 2) {
    self->extnId_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
    self->critical_ = false;
    self->value_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]);
  }
  else if ([seq size] == 3) {
    self->extnId_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
    self->critical_ = [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(OrgSpongycastleAsn1ASN1Boolean_getInstanceWithId_([seq getObjectAtWithInt:1]))) isTrue];
    self->value_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
}

OrgSpongycastleAsn1X509Extension *new_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509Extension *create_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509Extension, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509Extension *OrgSpongycastleAsn1X509Extension_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509Extension_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509Extension class]]) {
    return (OrgSpongycastleAsn1X509Extension *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1X509Extension_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

OrgSpongycastleAsn1ASN1Primitive *OrgSpongycastleAsn1X509Extension_convertValueToObjectWithOrgSpongycastleAsn1X509Extension_(OrgSpongycastleAsn1X509Extension *ext) {
  OrgSpongycastleAsn1X509Extension_initialize();
  @try {
    return OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk([((OrgSpongycastleAsn1X509Extension *) nil_chk(ext)) getExtnValue])) getOctets]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"can't convert extension: ", e));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509Extension)