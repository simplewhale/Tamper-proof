//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/AuthEnvelopedData.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedData")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsAuthEnvelopedData
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedData 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedData 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsAuthEnvelopedData

#if !defined (OrgSpongycastleAsn1CmsAuthEnvelopedData_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedData || defined(INCLUDE_OrgSpongycastleAsn1CmsAuthEnvelopedData))
#define OrgSpongycastleAsn1CmsAuthEnvelopedData_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Set;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@class OrgSpongycastleAsn1CmsEncryptedContentInfo;
@class OrgSpongycastleAsn1CmsOriginatorInfo;

@interface OrgSpongycastleAsn1CmsAuthEnvelopedData : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CmsOriginatorInfo:(OrgSpongycastleAsn1CmsOriginatorInfo *)originatorInfo
                              withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)recipientInfos
              withOrgSpongycastleAsn1CmsEncryptedContentInfo:(OrgSpongycastleAsn1CmsEncryptedContentInfo *)authEncryptedContentInfo
                              withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)authAttrs
                      withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)mac
                              withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)unauthAttrs;

- (OrgSpongycastleAsn1ASN1Set *)getAuthAttrs;

- (OrgSpongycastleAsn1CmsEncryptedContentInfo *)getAuthEncryptedContentInfo;

+ (OrgSpongycastleAsn1CmsAuthEnvelopedData *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1CmsAuthEnvelopedData *)getInstanceWithId:(id)obj;

- (OrgSpongycastleAsn1ASN1OctetString *)getMac;

- (OrgSpongycastleAsn1CmsOriginatorInfo *)getOriginatorInfo;

- (OrgSpongycastleAsn1ASN1Set *)getRecipientInfos;

- (OrgSpongycastleAsn1ASN1Set *)getUnauthAttrs;

- (OrgSpongycastleAsn1ASN1Integer *)getVersion;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsAuthEnvelopedData)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsAuthEnvelopedData *self, OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo, OrgSpongycastleAsn1ASN1Set *recipientInfos, OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo, OrgSpongycastleAsn1ASN1Set *authAttrs, OrgSpongycastleAsn1ASN1OctetString *mac, OrgSpongycastleAsn1ASN1Set *unauthAttrs);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAuthEnvelopedData *new_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo, OrgSpongycastleAsn1ASN1Set *recipientInfos, OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo, OrgSpongycastleAsn1ASN1Set *authAttrs, OrgSpongycastleAsn1ASN1OctetString *mac, OrgSpongycastleAsn1ASN1Set *unauthAttrs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAuthEnvelopedData *create_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo, OrgSpongycastleAsn1ASN1Set *recipientInfos, OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo, OrgSpongycastleAsn1ASN1Set *authAttrs, OrgSpongycastleAsn1ASN1OctetString *mac, OrgSpongycastleAsn1ASN1Set *unauthAttrs);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAuthEnvelopedData *OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAuthEnvelopedData *OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsAuthEnvelopedData)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedData")