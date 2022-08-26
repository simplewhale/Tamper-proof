//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/CMSAttributes.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/cms/CMSAttributes.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1CmsCMSAttributes)

OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CmsCMSAttributes_contentType;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CmsCMSAttributes_messageDigest;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CmsCMSAttributes_signingTime;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CmsCMSAttributes_counterSignature;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CmsCMSAttributes_contentHint;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CmsCMSAttributes_cmsAlgorithmProtect;

@implementation OrgSpongycastleAsn1CmsCMSAttributes

+ (const J2ObjcClassInfo *)__metadata {
  static const J2ObjcFieldInfo fields[] = {
    { "contentType", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "messageDigest", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "signingTime", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "counterSignature", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "contentHint", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "cmsAlgorithmProtect", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 5, -1, -1 },
  };
  static const void *ptrTable[] = { &OrgSpongycastleAsn1CmsCMSAttributes_contentType, &OrgSpongycastleAsn1CmsCMSAttributes_messageDigest, &OrgSpongycastleAsn1CmsCMSAttributes_signingTime, &OrgSpongycastleAsn1CmsCMSAttributes_counterSignature, &OrgSpongycastleAsn1CmsCMSAttributes_contentHint, &OrgSpongycastleAsn1CmsCMSAttributes_cmsAlgorithmProtect };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsCMSAttributes = { "CMSAttributes", "org.spongycastle.asn1.cms", ptrTable, NULL, fields, 7, 0x609, 0, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsCMSAttributes;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1CmsCMSAttributes class]) {
    OrgSpongycastleAsn1CmsCMSAttributes_contentType = JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, pkcs_9_at_contentType);
    OrgSpongycastleAsn1CmsCMSAttributes_messageDigest = JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, pkcs_9_at_messageDigest);
    OrgSpongycastleAsn1CmsCMSAttributes_signingTime = JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, pkcs_9_at_signingTime);
    OrgSpongycastleAsn1CmsCMSAttributes_counterSignature = JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, pkcs_9_at_counterSignature);
    OrgSpongycastleAsn1CmsCMSAttributes_contentHint = JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_aa_contentHint);
    OrgSpongycastleAsn1CmsCMSAttributes_cmsAlgorithmProtect = JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_aa_cmsAlgorithmProtect);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1CmsCMSAttributes)
  }
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsCMSAttributes)
