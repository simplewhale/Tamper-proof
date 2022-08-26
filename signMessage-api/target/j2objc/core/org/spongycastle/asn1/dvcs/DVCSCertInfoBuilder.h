//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/dvcs/DVCSCertInfoBuilder.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder")
#ifdef RESTRICT_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder
#define INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder

#if !defined (OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder_) && (INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder || defined(INCLUDE_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder))
#define OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder_

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Set;
@class OrgSpongycastleAsn1CmpPKIStatusInfo;
@class OrgSpongycastleAsn1DvcsDVCSCertInfo;
@class OrgSpongycastleAsn1DvcsDVCSRequestInformation;
@class OrgSpongycastleAsn1DvcsDVCSTime;
@class OrgSpongycastleAsn1X509DigestInfo;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509PolicyInformation;

@interface OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation:(OrgSpongycastleAsn1DvcsDVCSRequestInformation *)dvReqInfo
                                withOrgSpongycastleAsn1X509DigestInfo:(OrgSpongycastleAsn1X509DigestInfo *)messageImprint
                                   withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)serialNumber
                                  withOrgSpongycastleAsn1DvcsDVCSTime:(OrgSpongycastleAsn1DvcsDVCSTime *)responseTime;

- (OrgSpongycastleAsn1DvcsDVCSCertInfo *)build;

- (void)setCertsWithOrgSpongycastleAsn1DvcsTargetEtcChainArray:(IOSObjectArray *)certs;

- (void)setDvReqInfoWithOrgSpongycastleAsn1DvcsDVCSRequestInformation:(OrgSpongycastleAsn1DvcsDVCSRequestInformation *)dvReqInfo;

- (void)setDvStatusWithOrgSpongycastleAsn1CmpPKIStatusInfo:(OrgSpongycastleAsn1CmpPKIStatusInfo *)dvStatus;

- (void)setExtensionsWithOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions;

- (void)setMessageImprintWithOrgSpongycastleAsn1X509DigestInfo:(OrgSpongycastleAsn1X509DigestInfo *)messageImprint;

- (void)setPolicyWithOrgSpongycastleAsn1X509PolicyInformation:(OrgSpongycastleAsn1X509PolicyInformation *)policy;

- (void)setReqSignatureWithOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)reqSignature;

- (void)setResponseTimeWithOrgSpongycastleAsn1DvcsDVCSTime:(OrgSpongycastleAsn1DvcsDVCSTime *)responseTime;

- (void)setSerialNumberWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)serialNumber;

- (void)setVersionWithInt:(jint)version_;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder)

FOUNDATION_EXPORT void OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder_initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation_withOrgSpongycastleAsn1X509DigestInfo_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1DvcsDVCSTime_(OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder *self, OrgSpongycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, OrgSpongycastleAsn1X509DigestInfo *messageImprint, OrgSpongycastleAsn1ASN1Integer *serialNumber, OrgSpongycastleAsn1DvcsDVCSTime *responseTime);

FOUNDATION_EXPORT OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder *new_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder_initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation_withOrgSpongycastleAsn1X509DigestInfo_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1DvcsDVCSTime_(OrgSpongycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, OrgSpongycastleAsn1X509DigestInfo *messageImprint, OrgSpongycastleAsn1ASN1Integer *serialNumber, OrgSpongycastleAsn1DvcsDVCSTime *responseTime) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder *create_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder_initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation_withOrgSpongycastleAsn1X509DigestInfo_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1DvcsDVCSTime_(OrgSpongycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, OrgSpongycastleAsn1X509DigestInfo *messageImprint, OrgSpongycastleAsn1ASN1Integer *serialNumber, OrgSpongycastleAsn1DvcsDVCSTime *responseTime);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSCertInfoBuilder")
