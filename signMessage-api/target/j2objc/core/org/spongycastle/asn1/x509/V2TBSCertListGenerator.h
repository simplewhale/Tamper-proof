//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/V2TBSCertListGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509V2TBSCertListGenerator")
#ifdef RESTRICT_OrgSpongycastleAsn1X509V2TBSCertListGenerator
#define INCLUDE_ALL_OrgSpongycastleAsn1X509V2TBSCertListGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509V2TBSCertListGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509V2TBSCertListGenerator

#if !defined (OrgSpongycastleAsn1X509V2TBSCertListGenerator_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509V2TBSCertListGenerator || defined(INCLUDE_OrgSpongycastleAsn1X509V2TBSCertListGenerator))
#define OrgSpongycastleAsn1X509V2TBSCertListGenerator_

@class OrgSpongycastleAsn1ASN1GeneralizedTime;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1ASN1UTCTime;
@class OrgSpongycastleAsn1X500X500Name;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509TBSCertList;
@class OrgSpongycastleAsn1X509Time;
@class OrgSpongycastleAsn1X509X509Extensions;
@class OrgSpongycastleAsn1X509X509Name;

@interface OrgSpongycastleAsn1X509V2TBSCertListGenerator : NSObject

#pragma mark Public

- (instancetype)init;

- (void)addCRLEntryWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)userCertificate
                   withOrgSpongycastleAsn1ASN1UTCTime:(OrgSpongycastleAsn1ASN1UTCTime *)revocationDate
                                              withInt:(jint)reason;

- (void)addCRLEntryWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)userCertificate
                      withOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)revocationDate
                withOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions;

- (void)addCRLEntryWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)userCertificate
                      withOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)revocationDate
                                              withInt:(jint)reason;

- (void)addCRLEntryWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)userCertificate
                      withOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)revocationDate
                                              withInt:(jint)reason
           withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)invalidityDate;

- (void)addCRLEntryWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)crlEntry;

- (OrgSpongycastleAsn1X509TBSCertList *)generateTBSCertList;

- (void)setExtensionsWithOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions;

- (void)setExtensionsWithOrgSpongycastleAsn1X509X509Extensions:(OrgSpongycastleAsn1X509X509Extensions *)extensions;

- (void)setIssuerWithOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)issuer;

- (void)setIssuerWithOrgSpongycastleAsn1X509X509Name:(OrgSpongycastleAsn1X509X509Name *)issuer;

- (void)setNextUpdateWithOrgSpongycastleAsn1ASN1UTCTime:(OrgSpongycastleAsn1ASN1UTCTime *)nextUpdate;

- (void)setNextUpdateWithOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)nextUpdate;

- (void)setSignatureWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)signature;

- (void)setThisUpdateWithOrgSpongycastleAsn1ASN1UTCTime:(OrgSpongycastleAsn1ASN1UTCTime *)thisUpdate;

- (void)setThisUpdateWithOrgSpongycastleAsn1X509Time:(OrgSpongycastleAsn1X509Time *)thisUpdate;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1X509V2TBSCertListGenerator)

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509V2TBSCertListGenerator_init(OrgSpongycastleAsn1X509V2TBSCertListGenerator *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509V2TBSCertListGenerator *new_OrgSpongycastleAsn1X509V2TBSCertListGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509V2TBSCertListGenerator *create_OrgSpongycastleAsn1X509V2TBSCertListGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509V2TBSCertListGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509V2TBSCertListGenerator")
