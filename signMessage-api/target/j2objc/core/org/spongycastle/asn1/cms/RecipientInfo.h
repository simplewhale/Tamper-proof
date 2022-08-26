//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/RecipientInfo.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsRecipientInfo")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsRecipientInfo
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsRecipientInfo 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsRecipientInfo 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsRecipientInfo

#if !defined (OrgSpongycastleAsn1CmsRecipientInfo_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsRecipientInfo || defined(INCLUDE_OrgSpongycastleAsn1CmsRecipientInfo))
#define OrgSpongycastleAsn1CmsRecipientInfo_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

#define RESTRICT_OrgSpongycastleAsn1ASN1Choice 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Choice 1
#include "org/spongycastle/asn1/ASN1Choice.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1CmsKEKRecipientInfo;
@class OrgSpongycastleAsn1CmsKeyAgreeRecipientInfo;
@class OrgSpongycastleAsn1CmsKeyTransRecipientInfo;
@class OrgSpongycastleAsn1CmsOtherRecipientInfo;
@class OrgSpongycastleAsn1CmsPasswordRecipientInfo;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1CmsRecipientInfo : OrgSpongycastleAsn1ASN1Object < OrgSpongycastleAsn1ASN1Choice > {
 @public
  id<OrgSpongycastleAsn1ASN1Encodable> info_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)info;

- (instancetype)initWithOrgSpongycastleAsn1CmsKEKRecipientInfo:(OrgSpongycastleAsn1CmsKEKRecipientInfo *)info;

- (instancetype)initWithOrgSpongycastleAsn1CmsKeyAgreeRecipientInfo:(OrgSpongycastleAsn1CmsKeyAgreeRecipientInfo *)info;

- (instancetype)initWithOrgSpongycastleAsn1CmsKeyTransRecipientInfo:(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *)info;

- (instancetype)initWithOrgSpongycastleAsn1CmsOtherRecipientInfo:(OrgSpongycastleAsn1CmsOtherRecipientInfo *)info;

- (instancetype)initWithOrgSpongycastleAsn1CmsPasswordRecipientInfo:(OrgSpongycastleAsn1CmsPasswordRecipientInfo *)info;

- (id<OrgSpongycastleAsn1ASN1Encodable>)getInfo;

+ (OrgSpongycastleAsn1CmsRecipientInfo *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Integer *)getVersion;

- (jboolean)isTagged;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsRecipientInfo)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsRecipientInfo, info_, id<OrgSpongycastleAsn1ASN1Encodable>)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKeyTransRecipientInfo_(OrgSpongycastleAsn1CmsRecipientInfo *self, OrgSpongycastleAsn1CmsKeyTransRecipientInfo *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *new_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKeyTransRecipientInfo_(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *create_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKeyTransRecipientInfo_(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *info);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKeyAgreeRecipientInfo_(OrgSpongycastleAsn1CmsRecipientInfo *self, OrgSpongycastleAsn1CmsKeyAgreeRecipientInfo *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *new_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKeyAgreeRecipientInfo_(OrgSpongycastleAsn1CmsKeyAgreeRecipientInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *create_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKeyAgreeRecipientInfo_(OrgSpongycastleAsn1CmsKeyAgreeRecipientInfo *info);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKEKRecipientInfo_(OrgSpongycastleAsn1CmsRecipientInfo *self, OrgSpongycastleAsn1CmsKEKRecipientInfo *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *new_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKEKRecipientInfo_(OrgSpongycastleAsn1CmsKEKRecipientInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *create_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsKEKRecipientInfo_(OrgSpongycastleAsn1CmsKEKRecipientInfo *info);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsPasswordRecipientInfo_(OrgSpongycastleAsn1CmsRecipientInfo *self, OrgSpongycastleAsn1CmsPasswordRecipientInfo *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *new_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsPasswordRecipientInfo_(OrgSpongycastleAsn1CmsPasswordRecipientInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *create_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsPasswordRecipientInfo_(OrgSpongycastleAsn1CmsPasswordRecipientInfo *info);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsOtherRecipientInfo_(OrgSpongycastleAsn1CmsRecipientInfo *self, OrgSpongycastleAsn1CmsOtherRecipientInfo *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *new_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsOtherRecipientInfo_(OrgSpongycastleAsn1CmsOtherRecipientInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *create_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1CmsOtherRecipientInfo_(OrgSpongycastleAsn1CmsOtherRecipientInfo *info);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1CmsRecipientInfo *self, OrgSpongycastleAsn1ASN1Primitive *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *new_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *create_OrgSpongycastleAsn1CmsRecipientInfo_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *info);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsRecipientInfo *OrgSpongycastleAsn1CmsRecipientInfo_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsRecipientInfo)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsRecipientInfo")