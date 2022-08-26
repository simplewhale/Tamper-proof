//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/KeyTransRecipientInfo.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsKeyTransRecipientInfo")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsKeyTransRecipientInfo
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsKeyTransRecipientInfo 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsKeyTransRecipientInfo 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsKeyTransRecipientInfo

#if !defined (OrgSpongycastleAsn1CmsKeyTransRecipientInfo_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsKeyTransRecipientInfo || defined(INCLUDE_OrgSpongycastleAsn1CmsKeyTransRecipientInfo))
#define OrgSpongycastleAsn1CmsKeyTransRecipientInfo_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1CmsRecipientIdentifier;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;

@interface OrgSpongycastleAsn1CmsKeyTransRecipientInfo : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (instancetype)initWithOrgSpongycastleAsn1CmsRecipientIdentifier:(OrgSpongycastleAsn1CmsRecipientIdentifier *)rid
                   withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyEncryptionAlgorithm
                           withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)encryptedKey;

- (OrgSpongycastleAsn1ASN1OctetString *)getEncryptedKey;

+ (OrgSpongycastleAsn1CmsKeyTransRecipientInfo *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getKeyEncryptionAlgorithm;

- (OrgSpongycastleAsn1CmsRecipientIdentifier *)getRecipientIdentifier;

- (OrgSpongycastleAsn1ASN1Integer *)getVersion;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsKeyTransRecipientInfo)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *self, OrgSpongycastleAsn1CmsRecipientIdentifier *rid, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, OrgSpongycastleAsn1ASN1OctetString *encryptedKey);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsKeyTransRecipientInfo *new_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsRecipientIdentifier *rid, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, OrgSpongycastleAsn1ASN1OctetString *encryptedKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsKeyTransRecipientInfo *create_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsRecipientIdentifier *rid, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, OrgSpongycastleAsn1ASN1OctetString *encryptedKey);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsKeyTransRecipientInfo *new_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsKeyTransRecipientInfo *create_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsKeyTransRecipientInfo *OrgSpongycastleAsn1CmsKeyTransRecipientInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsKeyTransRecipientInfo)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsKeyTransRecipientInfo")
