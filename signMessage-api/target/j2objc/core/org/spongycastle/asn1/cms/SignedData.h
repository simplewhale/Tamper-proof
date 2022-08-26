//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/SignedData.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsSignedData")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsSignedData
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsSignedData 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsSignedData 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsSignedData

#if !defined (OrgSpongycastleAsn1CmsSignedData_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsSignedData || defined(INCLUDE_OrgSpongycastleAsn1CmsSignedData))
#define OrgSpongycastleAsn1CmsSignedData_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Set;
@class OrgSpongycastleAsn1CmsContentInfo;

@interface OrgSpongycastleAsn1CmsSignedData : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)digestAlgorithms
             withOrgSpongycastleAsn1CmsContentInfo:(OrgSpongycastleAsn1CmsContentInfo *)contentInfo
                    withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)certificates
                    withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)crls
                    withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)signerInfos;

- (OrgSpongycastleAsn1ASN1Set *)getCertificates;

- (OrgSpongycastleAsn1ASN1Set *)getCRLs;

- (OrgSpongycastleAsn1ASN1Set *)getDigestAlgorithms;

- (OrgSpongycastleAsn1CmsContentInfo *)getEncapContentInfo;

+ (OrgSpongycastleAsn1CmsSignedData *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Set *)getSignerInfos;

- (OrgSpongycastleAsn1ASN1Integer *)getVersion;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1CmsSignedData)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsSignedData *OrgSpongycastleAsn1CmsSignedData_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsSignedData_initWithOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsSignedData *self, OrgSpongycastleAsn1ASN1Set *digestAlgorithms, OrgSpongycastleAsn1CmsContentInfo *contentInfo, OrgSpongycastleAsn1ASN1Set *certificates, OrgSpongycastleAsn1ASN1Set *crls, OrgSpongycastleAsn1ASN1Set *signerInfos);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsSignedData *new_OrgSpongycastleAsn1CmsSignedData_initWithOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1Set *digestAlgorithms, OrgSpongycastleAsn1CmsContentInfo *contentInfo, OrgSpongycastleAsn1ASN1Set *certificates, OrgSpongycastleAsn1ASN1Set *crls, OrgSpongycastleAsn1ASN1Set *signerInfos) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsSignedData *create_OrgSpongycastleAsn1CmsSignedData_initWithOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1Set *digestAlgorithms, OrgSpongycastleAsn1CmsContentInfo *contentInfo, OrgSpongycastleAsn1ASN1Set *certificates, OrgSpongycastleAsn1ASN1Set *crls, OrgSpongycastleAsn1ASN1Set *signerInfos);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsSignedData)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsSignedData")
