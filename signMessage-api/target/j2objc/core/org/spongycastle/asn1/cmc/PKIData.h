//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/PKIData.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIData")
#ifdef RESTRICT_OrgSpongycastleAsn1CmcPKIData
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIData 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIData 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmcPKIData

#if !defined (OrgSpongycastleAsn1CmcPKIData_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIData || defined(INCLUDE_OrgSpongycastleAsn1CmcPKIData))
#define OrgSpongycastleAsn1CmcPKIData_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1CmcPKIData : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CmcTaggedAttributeArray:(IOSObjectArray *)controlSequence
                      withOrgSpongycastleAsn1CmcTaggedRequestArray:(IOSObjectArray *)reqSequence
                  withOrgSpongycastleAsn1CmcTaggedContentInfoArray:(IOSObjectArray *)cmsSequence
                           withOrgSpongycastleAsn1CmcOtherMsgArray:(IOSObjectArray *)otherMsgSequence;

- (IOSObjectArray *)getCmsSequence;

- (IOSObjectArray *)getControlSequence;

+ (OrgSpongycastleAsn1CmcPKIData *)getInstanceWithId:(id)src;

- (IOSObjectArray *)getOtherMsgSequence;

- (IOSObjectArray *)getReqSequence;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmcPKIData)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmcPKIData_initWithOrgSpongycastleAsn1CmcTaggedAttributeArray_withOrgSpongycastleAsn1CmcTaggedRequestArray_withOrgSpongycastleAsn1CmcTaggedContentInfoArray_withOrgSpongycastleAsn1CmcOtherMsgArray_(OrgSpongycastleAsn1CmcPKIData *self, IOSObjectArray *controlSequence, IOSObjectArray *reqSequence, IOSObjectArray *cmsSequence, IOSObjectArray *otherMsgSequence);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcPKIData *new_OrgSpongycastleAsn1CmcPKIData_initWithOrgSpongycastleAsn1CmcTaggedAttributeArray_withOrgSpongycastleAsn1CmcTaggedRequestArray_withOrgSpongycastleAsn1CmcTaggedContentInfoArray_withOrgSpongycastleAsn1CmcOtherMsgArray_(IOSObjectArray *controlSequence, IOSObjectArray *reqSequence, IOSObjectArray *cmsSequence, IOSObjectArray *otherMsgSequence) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcPKIData *create_OrgSpongycastleAsn1CmcPKIData_initWithOrgSpongycastleAsn1CmcTaggedAttributeArray_withOrgSpongycastleAsn1CmcTaggedRequestArray_withOrgSpongycastleAsn1CmcTaggedContentInfoArray_withOrgSpongycastleAsn1CmcOtherMsgArray_(IOSObjectArray *controlSequence, IOSObjectArray *reqSequence, IOSObjectArray *cmsSequence, IOSObjectArray *otherMsgSequence);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcPKIData *OrgSpongycastleAsn1CmcPKIData_getInstanceWithId_(id src);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmcPKIData)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcPKIData")
