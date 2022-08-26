//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/ErrorMsgContent.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpErrorMsgContent")
#ifdef RESTRICT_OrgSpongycastleAsn1CmpErrorMsgContent
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpErrorMsgContent 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpErrorMsgContent 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmpErrorMsgContent

#if !defined (OrgSpongycastleAsn1CmpErrorMsgContent_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmpErrorMsgContent || defined(INCLUDE_OrgSpongycastleAsn1CmpErrorMsgContent))
#define OrgSpongycastleAsn1CmpErrorMsgContent_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1CmpPKIFreeText;
@class OrgSpongycastleAsn1CmpPKIStatusInfo;

@interface OrgSpongycastleAsn1CmpErrorMsgContent : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CmpPKIStatusInfo:(OrgSpongycastleAsn1CmpPKIStatusInfo *)pkiStatusInfo;

- (instancetype)initWithOrgSpongycastleAsn1CmpPKIStatusInfo:(OrgSpongycastleAsn1CmpPKIStatusInfo *)pkiStatusInfo
                         withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)errorCode
                      withOrgSpongycastleAsn1CmpPKIFreeText:(OrgSpongycastleAsn1CmpPKIFreeText *)errorDetails;

- (OrgSpongycastleAsn1ASN1Integer *)getErrorCode;

- (OrgSpongycastleAsn1CmpPKIFreeText *)getErrorDetails;

+ (OrgSpongycastleAsn1CmpErrorMsgContent *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1CmpPKIStatusInfo *)getPKIStatusInfo;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmpErrorMsgContent)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpErrorMsgContent *OrgSpongycastleAsn1CmpErrorMsgContent_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpErrorMsgContent_initWithOrgSpongycastleAsn1CmpPKIStatusInfo_(OrgSpongycastleAsn1CmpErrorMsgContent *self, OrgSpongycastleAsn1CmpPKIStatusInfo *pkiStatusInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpErrorMsgContent *new_OrgSpongycastleAsn1CmpErrorMsgContent_initWithOrgSpongycastleAsn1CmpPKIStatusInfo_(OrgSpongycastleAsn1CmpPKIStatusInfo *pkiStatusInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpErrorMsgContent *create_OrgSpongycastleAsn1CmpErrorMsgContent_initWithOrgSpongycastleAsn1CmpPKIStatusInfo_(OrgSpongycastleAsn1CmpPKIStatusInfo *pkiStatusInfo);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpErrorMsgContent_initWithOrgSpongycastleAsn1CmpPKIStatusInfo_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1CmpPKIFreeText_(OrgSpongycastleAsn1CmpErrorMsgContent *self, OrgSpongycastleAsn1CmpPKIStatusInfo *pkiStatusInfo, OrgSpongycastleAsn1ASN1Integer *errorCode, OrgSpongycastleAsn1CmpPKIFreeText *errorDetails);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpErrorMsgContent *new_OrgSpongycastleAsn1CmpErrorMsgContent_initWithOrgSpongycastleAsn1CmpPKIStatusInfo_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1CmpPKIFreeText_(OrgSpongycastleAsn1CmpPKIStatusInfo *pkiStatusInfo, OrgSpongycastleAsn1ASN1Integer *errorCode, OrgSpongycastleAsn1CmpPKIFreeText *errorDetails) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpErrorMsgContent *create_OrgSpongycastleAsn1CmpErrorMsgContent_initWithOrgSpongycastleAsn1CmpPKIStatusInfo_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1CmpPKIFreeText_(OrgSpongycastleAsn1CmpPKIStatusInfo *pkiStatusInfo, OrgSpongycastleAsn1ASN1Integer *errorCode, OrgSpongycastleAsn1CmpPKIFreeText *errorDetails);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmpErrorMsgContent)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpErrorMsgContent")
