//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/FixedPointPreCompInfo.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcFixedPointPreCompInfo")
#ifdef RESTRICT_OrgSpongycastleMathEcFixedPointPreCompInfo
#define INCLUDE_ALL_OrgSpongycastleMathEcFixedPointPreCompInfo 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcFixedPointPreCompInfo 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcFixedPointPreCompInfo

#if !defined (OrgSpongycastleMathEcFixedPointPreCompInfo_) && (INCLUDE_ALL_OrgSpongycastleMathEcFixedPointPreCompInfo || defined(INCLUDE_OrgSpongycastleMathEcFixedPointPreCompInfo))
#define OrgSpongycastleMathEcFixedPointPreCompInfo_

#define RESTRICT_OrgSpongycastleMathEcPreCompInfo 1
#define INCLUDE_OrgSpongycastleMathEcPreCompInfo 1
#include "org/spongycastle/math/ec/PreCompInfo.h"

@class IOSObjectArray;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcFixedPointPreCompInfo : NSObject < OrgSpongycastleMathEcPreCompInfo > {
 @public
  OrgSpongycastleMathEcECPoint *offset_;
  IOSObjectArray *preComp_;
  jint width_;
}

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleMathEcECPoint *)getOffset;

- (IOSObjectArray *)getPreComp;

- (jint)getWidth;

- (void)setOffsetWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)offset;

- (void)setPreCompWithOrgSpongycastleMathEcECPointArray:(IOSObjectArray *)preComp;

- (void)setWidthWithInt:(jint)width;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcFixedPointPreCompInfo)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcFixedPointPreCompInfo, offset_, OrgSpongycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcFixedPointPreCompInfo, preComp_, IOSObjectArray *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcFixedPointPreCompInfo_init(OrgSpongycastleMathEcFixedPointPreCompInfo *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcFixedPointPreCompInfo *new_OrgSpongycastleMathEcFixedPointPreCompInfo_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcFixedPointPreCompInfo *create_OrgSpongycastleMathEcFixedPointPreCompInfo_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcFixedPointPreCompInfo)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcFixedPointPreCompInfo")
