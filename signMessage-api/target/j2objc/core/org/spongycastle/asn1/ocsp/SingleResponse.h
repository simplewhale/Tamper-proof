//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ocsp/SingleResponse.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1OcspSingleResponse")
#ifdef RESTRICT_OrgSpongycastleAsn1OcspSingleResponse
#define INCLUDE_ALL_OrgSpongycastleAsn1OcspSingleResponse 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1OcspSingleResponse 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1OcspSingleResponse

#if !defined (OrgSpongycastleAsn1OcspSingleResponse_) && (INCLUDE_ALL_OrgSpongycastleAsn1OcspSingleResponse || defined(INCLUDE_OrgSpongycastleAsn1OcspSingleResponse))
#define OrgSpongycastleAsn1OcspSingleResponse_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1GeneralizedTime;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1OcspCertID;
@class OrgSpongycastleAsn1OcspCertStatus;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509X509Extensions;

@interface OrgSpongycastleAsn1OcspSingleResponse : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1OcspCertID:(OrgSpongycastleAsn1OcspCertID *)certID
                withOrgSpongycastleAsn1OcspCertStatus:(OrgSpongycastleAsn1OcspCertStatus *)certStatus
           withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)thisUpdate
           withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)nextUpdate
                withOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)singleExtensions;

- (instancetype)initWithOrgSpongycastleAsn1OcspCertID:(OrgSpongycastleAsn1OcspCertID *)certID
                withOrgSpongycastleAsn1OcspCertStatus:(OrgSpongycastleAsn1OcspCertStatus *)certStatus
           withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)thisUpdate
           withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)nextUpdate
            withOrgSpongycastleAsn1X509X509Extensions:(OrgSpongycastleAsn1X509X509Extensions *)singleExtensions;

- (OrgSpongycastleAsn1OcspCertID *)getCertID;

- (OrgSpongycastleAsn1OcspCertStatus *)getCertStatus;

+ (OrgSpongycastleAsn1OcspSingleResponse *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                  withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1OcspSingleResponse *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getNextUpdate;

- (OrgSpongycastleAsn1X509Extensions *)getSingleExtensions;

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getThisUpdate;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1OcspSingleResponse)

FOUNDATION_EXPORT void OrgSpongycastleAsn1OcspSingleResponse_initWithOrgSpongycastleAsn1OcspCertID_withOrgSpongycastleAsn1OcspCertStatus_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1OcspSingleResponse *self, OrgSpongycastleAsn1OcspCertID *certID, OrgSpongycastleAsn1OcspCertStatus *certStatus, OrgSpongycastleAsn1ASN1GeneralizedTime *thisUpdate, OrgSpongycastleAsn1ASN1GeneralizedTime *nextUpdate, OrgSpongycastleAsn1X509X509Extensions *singleExtensions);

FOUNDATION_EXPORT OrgSpongycastleAsn1OcspSingleResponse *new_OrgSpongycastleAsn1OcspSingleResponse_initWithOrgSpongycastleAsn1OcspCertID_withOrgSpongycastleAsn1OcspCertStatus_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1OcspCertID *certID, OrgSpongycastleAsn1OcspCertStatus *certStatus, OrgSpongycastleAsn1ASN1GeneralizedTime *thisUpdate, OrgSpongycastleAsn1ASN1GeneralizedTime *nextUpdate, OrgSpongycastleAsn1X509X509Extensions *singleExtensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1OcspSingleResponse *create_OrgSpongycastleAsn1OcspSingleResponse_initWithOrgSpongycastleAsn1OcspCertID_withOrgSpongycastleAsn1OcspCertStatus_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1OcspCertID *certID, OrgSpongycastleAsn1OcspCertStatus *certStatus, OrgSpongycastleAsn1ASN1GeneralizedTime *thisUpdate, OrgSpongycastleAsn1ASN1GeneralizedTime *nextUpdate, OrgSpongycastleAsn1X509X509Extensions *singleExtensions);

FOUNDATION_EXPORT void OrgSpongycastleAsn1OcspSingleResponse_initWithOrgSpongycastleAsn1OcspCertID_withOrgSpongycastleAsn1OcspCertStatus_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1OcspSingleResponse *self, OrgSpongycastleAsn1OcspCertID *certID, OrgSpongycastleAsn1OcspCertStatus *certStatus, OrgSpongycastleAsn1ASN1GeneralizedTime *thisUpdate, OrgSpongycastleAsn1ASN1GeneralizedTime *nextUpdate, OrgSpongycastleAsn1X509Extensions *singleExtensions);

FOUNDATION_EXPORT OrgSpongycastleAsn1OcspSingleResponse *new_OrgSpongycastleAsn1OcspSingleResponse_initWithOrgSpongycastleAsn1OcspCertID_withOrgSpongycastleAsn1OcspCertStatus_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1OcspCertID *certID, OrgSpongycastleAsn1OcspCertStatus *certStatus, OrgSpongycastleAsn1ASN1GeneralizedTime *thisUpdate, OrgSpongycastleAsn1ASN1GeneralizedTime *nextUpdate, OrgSpongycastleAsn1X509Extensions *singleExtensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1OcspSingleResponse *create_OrgSpongycastleAsn1OcspSingleResponse_initWithOrgSpongycastleAsn1OcspCertID_withOrgSpongycastleAsn1OcspCertStatus_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1OcspCertID *certID, OrgSpongycastleAsn1OcspCertStatus *certStatus, OrgSpongycastleAsn1ASN1GeneralizedTime *thisUpdate, OrgSpongycastleAsn1ASN1GeneralizedTime *nextUpdate, OrgSpongycastleAsn1X509Extensions *singleExtensions);

FOUNDATION_EXPORT OrgSpongycastleAsn1OcspSingleResponse *OrgSpongycastleAsn1OcspSingleResponse_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1OcspSingleResponse *OrgSpongycastleAsn1OcspSingleResponse_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1OcspSingleResponse)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1OcspSingleResponse")