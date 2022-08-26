//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/TimeStampTokenEvidence.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsTimeStampTokenEvidence")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsTimeStampTokenEvidence
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsTimeStampTokenEvidence 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsTimeStampTokenEvidence 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsTimeStampTokenEvidence

#if !defined (OrgSpongycastleAsn1CmsTimeStampTokenEvidence_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsTimeStampTokenEvidence || defined(INCLUDE_OrgSpongycastleAsn1CmsTimeStampTokenEvidence))
#define OrgSpongycastleAsn1CmsTimeStampTokenEvidence_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1CmsTimeStampAndCRL;

@interface OrgSpongycastleAsn1CmsTimeStampTokenEvidence : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CmsTimeStampAndCRL:(OrgSpongycastleAsn1CmsTimeStampAndCRL *)timeStampAndCRL;

- (instancetype)initWithOrgSpongycastleAsn1CmsTimeStampAndCRLArray:(IOSObjectArray *)timeStampAndCRLs;

+ (OrgSpongycastleAsn1CmsTimeStampTokenEvidence *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)tagged
                                                                                         withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1CmsTimeStampTokenEvidence *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

- (IOSObjectArray *)toTimeStampAndCRLArray;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsTimeStampTokenEvidence)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsTimeStampTokenEvidence_initWithOrgSpongycastleAsn1CmsTimeStampAndCRLArray_(OrgSpongycastleAsn1CmsTimeStampTokenEvidence *self, IOSObjectArray *timeStampAndCRLs);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsTimeStampTokenEvidence *new_OrgSpongycastleAsn1CmsTimeStampTokenEvidence_initWithOrgSpongycastleAsn1CmsTimeStampAndCRLArray_(IOSObjectArray *timeStampAndCRLs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsTimeStampTokenEvidence *create_OrgSpongycastleAsn1CmsTimeStampTokenEvidence_initWithOrgSpongycastleAsn1CmsTimeStampAndCRLArray_(IOSObjectArray *timeStampAndCRLs);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsTimeStampTokenEvidence_initWithOrgSpongycastleAsn1CmsTimeStampAndCRL_(OrgSpongycastleAsn1CmsTimeStampTokenEvidence *self, OrgSpongycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsTimeStampTokenEvidence *new_OrgSpongycastleAsn1CmsTimeStampTokenEvidence_initWithOrgSpongycastleAsn1CmsTimeStampAndCRL_(OrgSpongycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsTimeStampTokenEvidence *create_OrgSpongycastleAsn1CmsTimeStampTokenEvidence_initWithOrgSpongycastleAsn1CmsTimeStampAndCRL_(OrgSpongycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsTimeStampTokenEvidence *OrgSpongycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *tagged, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsTimeStampTokenEvidence *OrgSpongycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsTimeStampTokenEvidence)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsTimeStampTokenEvidence")