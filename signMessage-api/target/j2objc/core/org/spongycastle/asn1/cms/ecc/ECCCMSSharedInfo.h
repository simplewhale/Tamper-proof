//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/ecc/ECCCMSSharedInfo.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo

#if !defined (OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo || defined(INCLUDE_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo))
#define OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;

@interface OrgSpongycastleAsn1CmsEccECCCMSSharedInfo : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyInfo
                                                     withByteArray:(IOSByteArray *)suppPubInfo;

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyInfo
                                                     withByteArray:(IOSByteArray *)entityUInfo
                                                     withByteArray:(IOSByteArray *)suppPubInfo;

+ (OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsEccECCCMSSharedInfo)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyInfo, IOSByteArray *entityUInfo, IOSByteArray *suppPubInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *new_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyInfo, IOSByteArray *entityUInfo, IOSByteArray *suppPubInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *create_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyInfo, IOSByteArray *entityUInfo, IOSByteArray *suppPubInfo);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyInfo, IOSByteArray *suppPubInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *new_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyInfo, IOSByteArray *suppPubInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *create_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyInfo, IOSByteArray *suppPubInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEccECCCMSSharedInfo *OrgSpongycastleAsn1CmsEccECCCMSSharedInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsEccECCCMSSharedInfo)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsEccECCCMSSharedInfo")
