//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x500/X500NameStyle.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X500X500NameStyle")
#ifdef RESTRICT_OrgSpongycastleAsn1X500X500NameStyle
#define INCLUDE_ALL_OrgSpongycastleAsn1X500X500NameStyle 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X500X500NameStyle 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X500X500NameStyle

#if !defined (OrgSpongycastleAsn1X500X500NameStyle_) && (INCLUDE_ALL_OrgSpongycastleAsn1X500X500NameStyle || defined(INCLUDE_OrgSpongycastleAsn1X500X500NameStyle))
#define OrgSpongycastleAsn1X500X500NameStyle_

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1X500X500Name;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@protocol OrgSpongycastleAsn1X500X500NameStyle < JavaObject >

- (id<OrgSpongycastleAsn1ASN1Encodable>)stringToValueWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                    withNSString:(NSString *)value;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)attrNameToOIDWithNSString:(NSString *)attrName;

- (IOSObjectArray *)fromStringWithNSString:(NSString *)dirName;

- (jboolean)areEqualWithOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)name1
                    withOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)name2;

- (jint)calculateHashCodeWithOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)name;

- (NSString *)toStringWithOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)name;

- (NSString *)oidToDisplayNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

- (IOSObjectArray *)oidToAttrNamesWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X500X500NameStyle)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X500X500NameStyle)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X500X500NameStyle")
