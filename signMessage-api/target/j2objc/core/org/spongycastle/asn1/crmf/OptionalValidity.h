//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/OptionalValidity.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CrmfOptionalValidity")
#ifdef RESTRICT_OrgSpongycastleAsn1CrmfOptionalValidity
#define INCLUDE_ALL_OrgSpongycastleAsn1CrmfOptionalValidity 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CrmfOptionalValidity 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CrmfOptionalValidity

#if !defined (OrgSpongycastleAsn1CrmfOptionalValidity_) && (INCLUDE_ALL_OrgSpongycastleAsn1CrmfOptionalValidity || defined(INCLUDE_OrgSpongycastleAsn1CrmfOptionalValidity))
#define OrgSpongycastleAsn1CrmfOptionalValidity_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509Time;

@interface OrgSpongycastleAsn1CrmfOptionalValidity : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)notBefore
                    withOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)notAfter;

+ (OrgSpongycastleAsn1CrmfOptionalValidity *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1X509Time *)getNotAfter;

- (OrgSpongycastleAsn1X509Time *)getNotBefore;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CrmfOptionalValidity)

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfOptionalValidity *OrgSpongycastleAsn1CrmfOptionalValidity_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CrmfOptionalValidity_initWithOrgSpongycastleAsn1X509Time_withOrgSpongycastleAsn1X509Time_(OrgSpongycastleAsn1CrmfOptionalValidity *self, OrgSpongycastleAsn1X509Time *notBefore, OrgSpongycastleAsn1X509Time *notAfter);

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfOptionalValidity *new_OrgSpongycastleAsn1CrmfOptionalValidity_initWithOrgSpongycastleAsn1X509Time_withOrgSpongycastleAsn1X509Time_(OrgSpongycastleAsn1X509Time *notBefore, OrgSpongycastleAsn1X509Time *notAfter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CrmfOptionalValidity *create_OrgSpongycastleAsn1CrmfOptionalValidity_initWithOrgSpongycastleAsn1X509Time_withOrgSpongycastleAsn1X509Time_(OrgSpongycastleAsn1X509Time *notBefore, OrgSpongycastleAsn1X509Time *notAfter);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CrmfOptionalValidity)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CrmfOptionalValidity")
