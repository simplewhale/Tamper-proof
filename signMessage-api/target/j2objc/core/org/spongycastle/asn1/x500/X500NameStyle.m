//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x500/X500NameStyle.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/x500/X500NameStyle.h"

@interface OrgSpongycastleAsn1X500X500NameStyle : NSObject

@end

@implementation OrgSpongycastleAsn1X500X500NameStyle

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x401, 2, 3, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1X500RDN;", 0x401, 4, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x401, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x401, 7, 8, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, 9, 8, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, 10, 11, -1, -1, -1, -1 },
    { NULL, "[LNSString;", 0x401, 12, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(stringToValueWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withNSString:);
  methods[1].selector = @selector(attrNameToOIDWithNSString:);
  methods[2].selector = @selector(fromStringWithNSString:);
  methods[3].selector = @selector(areEqualWithOrgSpongycastleAsn1X500X500Name:withOrgSpongycastleAsn1X500X500Name:);
  methods[4].selector = @selector(calculateHashCodeWithOrgSpongycastleAsn1X500X500Name:);
  methods[5].selector = @selector(toStringWithOrgSpongycastleAsn1X500X500Name:);
  methods[6].selector = @selector(oidToDisplayNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  methods[7].selector = @selector(oidToAttrNamesWithOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "stringToValue", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LNSString;", "attrNameToOID", "LNSString;", "fromString", "areEqual", "LOrgSpongycastleAsn1X500X500Name;LOrgSpongycastleAsn1X500X500Name;", "calculateHashCode", "LOrgSpongycastleAsn1X500X500Name;", "toString", "oidToDisplayName", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", "oidToAttrNames" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X500X500NameStyle = { "X500NameStyle", "org.spongycastle.asn1.x500", ptrTable, methods, NULL, 7, 0x609, 8, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X500X500NameStyle;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X500X500NameStyle)
