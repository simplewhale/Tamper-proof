//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/IssuingDistributionPoint.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509IssuingDistributionPoint")
#ifdef RESTRICT_OrgSpongycastleAsn1X509IssuingDistributionPoint
#define INCLUDE_ALL_OrgSpongycastleAsn1X509IssuingDistributionPoint 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509IssuingDistributionPoint 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509IssuingDistributionPoint

#if !defined (OrgSpongycastleAsn1X509IssuingDistributionPoint_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509IssuingDistributionPoint || defined(INCLUDE_OrgSpongycastleAsn1X509IssuingDistributionPoint))
#define OrgSpongycastleAsn1X509IssuingDistributionPoint_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1X509DistributionPointName;
@class OrgSpongycastleAsn1X509ReasonFlags;

@interface OrgSpongycastleAsn1X509IssuingDistributionPoint : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509DistributionPointName:(OrgSpongycastleAsn1X509DistributionPointName *)distributionPoint
                                                         withBoolean:(jboolean)indirectCRL
                                                         withBoolean:(jboolean)onlyContainsAttributeCerts;

- (instancetype)initWithOrgSpongycastleAsn1X509DistributionPointName:(OrgSpongycastleAsn1X509DistributionPointName *)distributionPoint
                                                         withBoolean:(jboolean)onlyContainsUserCerts
                                                         withBoolean:(jboolean)onlyContainsCACerts
                              withOrgSpongycastleAsn1X509ReasonFlags:(OrgSpongycastleAsn1X509ReasonFlags *)onlySomeReasons
                                                         withBoolean:(jboolean)indirectCRL
                                                         withBoolean:(jboolean)onlyContainsAttributeCerts;

- (OrgSpongycastleAsn1X509DistributionPointName *)getDistributionPoint;

+ (OrgSpongycastleAsn1X509IssuingDistributionPoint *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                            withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X509IssuingDistributionPoint *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1X509ReasonFlags *)getOnlySomeReasons;

- (jboolean)isIndirectCRL;

- (jboolean)onlyContainsAttributeCerts;

- (jboolean)onlyContainsCACerts;

- (jboolean)onlyContainsUserCerts;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509IssuingDistributionPoint)

FOUNDATION_EXPORT OrgSpongycastleAsn1X509IssuingDistributionPoint *OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509IssuingDistributionPoint *OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509IssuingDistributionPoint *new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509IssuingDistributionPoint *create_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509IssuingDistributionPoint *new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509IssuingDistributionPoint *create_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509IssuingDistributionPoint)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509IssuingDistributionPoint")