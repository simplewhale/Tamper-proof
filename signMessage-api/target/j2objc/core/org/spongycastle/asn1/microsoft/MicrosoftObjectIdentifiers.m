//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/microsoft/MicrosoftObjectIdentifiers.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/microsoft/MicrosoftObjectIdentifiers.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers)

OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2;
OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies;

@implementation OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers

+ (const J2ObjcClassInfo *)__metadata {
  static const J2ObjcFieldInfo fields[] = {
    { "microsoft", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "microsoftCertTemplateV1", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "microsoftCaVersion", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "microsoftPrevCaCertHash", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "microsoftCrlNextPublish", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "microsoftCertTemplateV2", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 5, -1, -1 },
    { "microsoftAppPolicies", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
  };
  static const void *ptrTable[] = { &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft, &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1, &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion, &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash, &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish, &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2, &OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers = { "MicrosoftObjectIdentifiers", "org.spongycastle.asn1.microsoft", ptrTable, NULL, fields, 7, 0x609, 0, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers class]) {
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft = new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.4.1.311");
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV1 = [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"20.2"];
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCaVersion = [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.1"];
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftPrevCaCertHash = [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.2"];
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCrlNextPublish = [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.4"];
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftCertTemplateV2 = [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.7"];
    OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoftAppPolicies = [OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers_microsoft branchWithNSString:@"21.10"];
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers)
  }
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1MicrosoftMicrosoftObjectIdentifiers)
