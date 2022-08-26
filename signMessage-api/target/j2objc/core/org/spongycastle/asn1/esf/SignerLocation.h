//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/esf/SignerLocation.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EsfSignerLocation")
#ifdef RESTRICT_OrgSpongycastleAsn1EsfSignerLocation
#define INCLUDE_ALL_OrgSpongycastleAsn1EsfSignerLocation 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EsfSignerLocation 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EsfSignerLocation

#if !defined (OrgSpongycastleAsn1EsfSignerLocation_) && (INCLUDE_ALL_OrgSpongycastleAsn1EsfSignerLocation || defined(INCLUDE_OrgSpongycastleAsn1EsfSignerLocation))
#define OrgSpongycastleAsn1EsfSignerLocation_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1DERUTF8String;
@class OrgSpongycastleAsn1X500DirectoryString;

@interface OrgSpongycastleAsn1EsfSignerLocation : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1DERUTF8String:(OrgSpongycastleAsn1DERUTF8String *)countryName
                    withOrgSpongycastleAsn1DERUTF8String:(OrgSpongycastleAsn1DERUTF8String *)localityName
                     withOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)postalAddress;

- (instancetype)initWithOrgSpongycastleAsn1X500DirectoryString:(OrgSpongycastleAsn1X500DirectoryString *)countryName
                    withOrgSpongycastleAsn1X500DirectoryString:(OrgSpongycastleAsn1X500DirectoryString *)localityName
               withOrgSpongycastleAsn1X500DirectoryStringArray:(IOSObjectArray *)postalAddress;

- (OrgSpongycastleAsn1X500DirectoryString *)getCountry;

- (OrgSpongycastleAsn1DERUTF8String *)getCountryName;

+ (OrgSpongycastleAsn1EsfSignerLocation *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1X500DirectoryString *)getLocality;

- (OrgSpongycastleAsn1DERUTF8String *)getLocalityName;

- (IOSObjectArray *)getPostal;

- (OrgSpongycastleAsn1ASN1Sequence *)getPostalAddress;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EsfSignerLocation)

FOUNDATION_EXPORT void OrgSpongycastleAsn1EsfSignerLocation_initWithOrgSpongycastleAsn1X500DirectoryString_withOrgSpongycastleAsn1X500DirectoryString_withOrgSpongycastleAsn1X500DirectoryStringArray_(OrgSpongycastleAsn1EsfSignerLocation *self, OrgSpongycastleAsn1X500DirectoryString *countryName, OrgSpongycastleAsn1X500DirectoryString *localityName, IOSObjectArray *postalAddress);

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSignerLocation *new_OrgSpongycastleAsn1EsfSignerLocation_initWithOrgSpongycastleAsn1X500DirectoryString_withOrgSpongycastleAsn1X500DirectoryString_withOrgSpongycastleAsn1X500DirectoryStringArray_(OrgSpongycastleAsn1X500DirectoryString *countryName, OrgSpongycastleAsn1X500DirectoryString *localityName, IOSObjectArray *postalAddress) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSignerLocation *create_OrgSpongycastleAsn1EsfSignerLocation_initWithOrgSpongycastleAsn1X500DirectoryString_withOrgSpongycastleAsn1X500DirectoryString_withOrgSpongycastleAsn1X500DirectoryStringArray_(OrgSpongycastleAsn1X500DirectoryString *countryName, OrgSpongycastleAsn1X500DirectoryString *localityName, IOSObjectArray *postalAddress);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EsfSignerLocation_initWithOrgSpongycastleAsn1DERUTF8String_withOrgSpongycastleAsn1DERUTF8String_withOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EsfSignerLocation *self, OrgSpongycastleAsn1DERUTF8String *countryName, OrgSpongycastleAsn1DERUTF8String *localityName, OrgSpongycastleAsn1ASN1Sequence *postalAddress);

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSignerLocation *new_OrgSpongycastleAsn1EsfSignerLocation_initWithOrgSpongycastleAsn1DERUTF8String_withOrgSpongycastleAsn1DERUTF8String_withOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1DERUTF8String *countryName, OrgSpongycastleAsn1DERUTF8String *localityName, OrgSpongycastleAsn1ASN1Sequence *postalAddress) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSignerLocation *create_OrgSpongycastleAsn1EsfSignerLocation_initWithOrgSpongycastleAsn1DERUTF8String_withOrgSpongycastleAsn1DERUTF8String_withOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1DERUTF8String *countryName, OrgSpongycastleAsn1DERUTF8String *localityName, OrgSpongycastleAsn1ASN1Sequence *postalAddress);

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSignerLocation *OrgSpongycastleAsn1EsfSignerLocation_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EsfSignerLocation)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EsfSignerLocation")