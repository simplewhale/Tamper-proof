//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/NoticeReference.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509NoticeReference")
#ifdef RESTRICT_OrgSpongycastleAsn1X509NoticeReference
#define INCLUDE_ALL_OrgSpongycastleAsn1X509NoticeReference 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509NoticeReference 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509NoticeReference

#if !defined (OrgSpongycastleAsn1X509NoticeReference_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509NoticeReference || defined(INCLUDE_OrgSpongycastleAsn1X509NoticeReference))
#define OrgSpongycastleAsn1X509NoticeReference_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class JavaUtilVector;
@class OrgSpongycastleAsn1ASN1EncodableVector;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509DisplayText;

@interface OrgSpongycastleAsn1X509NoticeReference : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509DisplayText:(OrgSpongycastleAsn1X509DisplayText *)organization
                withOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)noticeNumbers;

- (instancetype)initWithNSString:(NSString *)organization
withOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)noticeNumbers;

- (instancetype)initWithNSString:(NSString *)organization
              withJavaUtilVector:(JavaUtilVector *)numbers;

+ (OrgSpongycastleAsn1X509NoticeReference *)getInstanceWithId:(id)as;

- (IOSObjectArray *)getNoticeNumbers;

- (OrgSpongycastleAsn1X509DisplayText *)getOrganization;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509NoticeReference)

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(OrgSpongycastleAsn1X509NoticeReference *self, NSString *organization, JavaUtilVector *numbers);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(NSString *organization, JavaUtilVector *numbers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(NSString *organization, JavaUtilVector *numbers);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509NoticeReference *self, NSString *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(NSString *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(NSString *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509NoticeReference *self, OrgSpongycastleAsn1X509DisplayText *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509DisplayText *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509DisplayText *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509NoticeReference *OrgSpongycastleAsn1X509NoticeReference_getInstanceWithId_(id as);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509NoticeReference)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509NoticeReference")