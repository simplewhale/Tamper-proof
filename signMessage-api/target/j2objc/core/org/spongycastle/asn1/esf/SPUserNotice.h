//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/esf/SPUserNotice.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EsfSPUserNotice")
#ifdef RESTRICT_OrgSpongycastleAsn1EsfSPUserNotice
#define INCLUDE_ALL_OrgSpongycastleAsn1EsfSPUserNotice 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EsfSPUserNotice 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EsfSPUserNotice

#if !defined (OrgSpongycastleAsn1EsfSPUserNotice_) && (INCLUDE_ALL_OrgSpongycastleAsn1EsfSPUserNotice || defined(INCLUDE_OrgSpongycastleAsn1EsfSPUserNotice))
#define OrgSpongycastleAsn1EsfSPUserNotice_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509DisplayText;
@class OrgSpongycastleAsn1X509NoticeReference;

@interface OrgSpongycastleAsn1EsfSPUserNotice : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509NoticeReference:(OrgSpongycastleAsn1X509NoticeReference *)noticeRef
                        withOrgSpongycastleAsn1X509DisplayText:(OrgSpongycastleAsn1X509DisplayText *)explicitText;

- (OrgSpongycastleAsn1X509DisplayText *)getExplicitText;

+ (OrgSpongycastleAsn1EsfSPUserNotice *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1X509NoticeReference *)getNoticeRef;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EsfSPUserNotice)

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSPUserNotice *OrgSpongycastleAsn1EsfSPUserNotice_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EsfSPUserNotice_initWithOrgSpongycastleAsn1X509NoticeReference_withOrgSpongycastleAsn1X509DisplayText_(OrgSpongycastleAsn1EsfSPUserNotice *self, OrgSpongycastleAsn1X509NoticeReference *noticeRef, OrgSpongycastleAsn1X509DisplayText *explicitText);

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSPUserNotice *new_OrgSpongycastleAsn1EsfSPUserNotice_initWithOrgSpongycastleAsn1X509NoticeReference_withOrgSpongycastleAsn1X509DisplayText_(OrgSpongycastleAsn1X509NoticeReference *noticeRef, OrgSpongycastleAsn1X509DisplayText *explicitText) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EsfSPUserNotice *create_OrgSpongycastleAsn1EsfSPUserNotice_initWithOrgSpongycastleAsn1X509NoticeReference_withOrgSpongycastleAsn1X509DisplayText_(OrgSpongycastleAsn1X509NoticeReference *noticeRef, OrgSpongycastleAsn1X509DisplayText *explicitText);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EsfSPUserNotice)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EsfSPUserNotice")
