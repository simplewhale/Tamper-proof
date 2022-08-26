//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/CMCStatusInfoBuilder.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder")
#ifdef RESTRICT_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder

#if !defined (OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder || defined(INCLUDE_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder))
#define OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_

@class IOSObjectArray;
@class OrgSpongycastleAsn1CmcBodyPartID;
@class OrgSpongycastleAsn1CmcCMCFailInfo;
@class OrgSpongycastleAsn1CmcCMCStatus;
@class OrgSpongycastleAsn1CmcCMCStatusInfo;
@class OrgSpongycastleAsn1CmcPendInfo;

@interface OrgSpongycastleAsn1CmcCMCStatusInfoBuilder : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1CmcCMCStatus:(OrgSpongycastleAsn1CmcCMCStatus *)cMCStatus
                   withOrgSpongycastleAsn1CmcBodyPartID:(OrgSpongycastleAsn1CmcBodyPartID *)bodyPartID;

- (instancetype)initWithOrgSpongycastleAsn1CmcCMCStatus:(OrgSpongycastleAsn1CmcCMCStatus *)cMCStatus
              withOrgSpongycastleAsn1CmcBodyPartIDArray:(IOSObjectArray *)bodyList;

- (OrgSpongycastleAsn1CmcCMCStatusInfo *)build;

- (OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *)setOtherInfoWithOrgSpongycastleAsn1CmcCMCFailInfo:(OrgSpongycastleAsn1CmcCMCFailInfo *)failInfo;

- (OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *)setOtherInfoWithOrgSpongycastleAsn1CmcPendInfo:(OrgSpongycastleAsn1CmcPendInfo *)pendInfo;

- (OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *)setStatusStringWithNSString:(NSString *)statusString;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmcCMCStatusInfoBuilder)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_initWithOrgSpongycastleAsn1CmcCMCStatus_withOrgSpongycastleAsn1CmcBodyPartID_(OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *self, OrgSpongycastleAsn1CmcCMCStatus *cMCStatus, OrgSpongycastleAsn1CmcBodyPartID *bodyPartID);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *new_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_initWithOrgSpongycastleAsn1CmcCMCStatus_withOrgSpongycastleAsn1CmcBodyPartID_(OrgSpongycastleAsn1CmcCMCStatus *cMCStatus, OrgSpongycastleAsn1CmcBodyPartID *bodyPartID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *create_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_initWithOrgSpongycastleAsn1CmcCMCStatus_withOrgSpongycastleAsn1CmcBodyPartID_(OrgSpongycastleAsn1CmcCMCStatus *cMCStatus, OrgSpongycastleAsn1CmcBodyPartID *bodyPartID);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_initWithOrgSpongycastleAsn1CmcCMCStatus_withOrgSpongycastleAsn1CmcBodyPartIDArray_(OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *self, OrgSpongycastleAsn1CmcCMCStatus *cMCStatus, IOSObjectArray *bodyList);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *new_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_initWithOrgSpongycastleAsn1CmcCMCStatus_withOrgSpongycastleAsn1CmcBodyPartIDArray_(OrgSpongycastleAsn1CmcCMCStatus *cMCStatus, IOSObjectArray *bodyList) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatusInfoBuilder *create_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder_initWithOrgSpongycastleAsn1CmcCMCStatus_withOrgSpongycastleAsn1CmcBodyPartIDArray_(OrgSpongycastleAsn1CmcCMCStatus *cMCStatus, IOSObjectArray *bodyList);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmcCMCStatusInfoBuilder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatusInfoBuilder")
