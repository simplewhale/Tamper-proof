//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/X509DefaultEntryConverter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509X509DefaultEntryConverter")
#ifdef RESTRICT_OrgSpongycastleAsn1X509X509DefaultEntryConverter
#define INCLUDE_ALL_OrgSpongycastleAsn1X509X509DefaultEntryConverter 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509X509DefaultEntryConverter 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509X509DefaultEntryConverter

#if !defined (OrgSpongycastleAsn1X509X509DefaultEntryConverter_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509X509DefaultEntryConverter || defined(INCLUDE_OrgSpongycastleAsn1X509X509DefaultEntryConverter))
#define OrgSpongycastleAsn1X509X509DefaultEntryConverter_

#define RESTRICT_OrgSpongycastleAsn1X509X509NameEntryConverter 1
#define INCLUDE_OrgSpongycastleAsn1X509X509NameEntryConverter 1
#include "org/spongycastle/asn1/x509/X509NameEntryConverter.h"

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1X509X509DefaultEntryConverter : OrgSpongycastleAsn1X509X509NameEntryConverter

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleAsn1ASN1Primitive *)getConvertedValueWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                      withNSString:(NSString *)value;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509X509DefaultEntryConverter)

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509X509DefaultEntryConverter_init(OrgSpongycastleAsn1X509X509DefaultEntryConverter *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509DefaultEntryConverter *new_OrgSpongycastleAsn1X509X509DefaultEntryConverter_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509X509DefaultEntryConverter *create_OrgSpongycastleAsn1X509X509DefaultEntryConverter_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509X509DefaultEntryConverter)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509X509DefaultEntryConverter")
