//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/CRMFObjectIdentifiers.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/crmf/CRMFObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers)

OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkix;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkip;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_regToken;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_authenticator;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_pkiPublicationInfo;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_pkiArchiveOptions;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_ct_encKeyWithID;

@implementation OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers

+ (const J2ObjcClassInfo *)__metadata {
  static const J2ObjcFieldInfo fields[] = {
    { "id_pkix", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "id_pkip", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "id_regCtrl", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "id_regCtrl_regToken", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "id_regCtrl_authenticator", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "id_regCtrl_pkiPublicationInfo", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 5, -1, -1 },
    { "id_regCtrl_pkiArchiveOptions", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
    { "id_ct_encKeyWithID", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 7, -1, -1 },
  };
  static const void *ptrTable[] = { &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkix, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkip, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_regToken, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_authenticator, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_pkiPublicationInfo, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_pkiArchiveOptions, &OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_ct_encKeyWithID };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers = { "CRMFObjectIdentifiers", "org.spongycastle.asn1.crmf", ptrTable, NULL, fields, 7, 0x609, 0, 8, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers class]) {
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkix = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7");
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkip = [OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkix branchWithNSString:@"5"];
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl = [((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_pkip)) branchWithNSString:@"1"];
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_regToken = [((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl)) branchWithNSString:@"1"];
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_authenticator = [OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl branchWithNSString:@"2"];
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_pkiPublicationInfo = [OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl branchWithNSString:@"3"];
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl_pkiArchiveOptions = [OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_regCtrl branchWithNSString:@"4"];
    OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers_id_ct_encKeyWithID = [((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_ct))) branchWithNSString:@"21"];
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers)
  }
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CrmfCRMFObjectIdentifiers)
