//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/GetCRL.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcGetCRL")
#ifdef RESTRICT_OrgSpongycastleAsn1CmcGetCRL
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcGetCRL 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcGetCRL 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmcGetCRL

#if !defined (OrgSpongycastleAsn1CmcGetCRL_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmcGetCRL || defined(INCLUDE_OrgSpongycastleAsn1CmcGetCRL))
#define OrgSpongycastleAsn1CmcGetCRL_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1GeneralizedTime;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X500X500Name;
@class OrgSpongycastleAsn1X509GeneralName;
@class OrgSpongycastleAsn1X509ReasonFlags;

@interface OrgSpongycastleAsn1CmcGetCRL : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)issuerName
                 withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)cRLName
             withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)time
                 withOrgSpongycastleAsn1X509ReasonFlags:(OrgSpongycastleAsn1X509ReasonFlags *)reasons;

- (OrgSpongycastleAsn1X509GeneralName *)getcRLName;

+ (OrgSpongycastleAsn1CmcGetCRL *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1X500X500Name *)getIssuerName;

- (OrgSpongycastleAsn1X509ReasonFlags *)getReasons;

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getTime;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmcGetCRL)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmcGetCRL_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509ReasonFlags_(OrgSpongycastleAsn1CmcGetCRL *self, OrgSpongycastleAsn1X500X500Name *issuerName, OrgSpongycastleAsn1X509GeneralName *cRLName, OrgSpongycastleAsn1ASN1GeneralizedTime *time, OrgSpongycastleAsn1X509ReasonFlags *reasons);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcGetCRL *new_OrgSpongycastleAsn1CmcGetCRL_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509ReasonFlags_(OrgSpongycastleAsn1X500X500Name *issuerName, OrgSpongycastleAsn1X509GeneralName *cRLName, OrgSpongycastleAsn1ASN1GeneralizedTime *time, OrgSpongycastleAsn1X509ReasonFlags *reasons) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcGetCRL *create_OrgSpongycastleAsn1CmcGetCRL_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X509ReasonFlags_(OrgSpongycastleAsn1X500X500Name *issuerName, OrgSpongycastleAsn1X509GeneralName *cRLName, OrgSpongycastleAsn1ASN1GeneralizedTime *time, OrgSpongycastleAsn1X509ReasonFlags *reasons);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcGetCRL *OrgSpongycastleAsn1CmcGetCRL_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmcGetCRL)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcGetCRL")
