//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/LICENSE.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleLICENSE")
#ifdef RESTRICT_OrgSpongycastleLICENSE
#define INCLUDE_ALL_OrgSpongycastleLICENSE 0
#else
#define INCLUDE_ALL_OrgSpongycastleLICENSE 1
#endif
#undef RESTRICT_OrgSpongycastleLICENSE

#if !defined (OrgSpongycastleLICENSE_) && (INCLUDE_ALL_OrgSpongycastleLICENSE || defined(INCLUDE_OrgSpongycastleLICENSE))
#define OrgSpongycastleLICENSE_

@class IOSObjectArray;

@interface OrgSpongycastleLICENSE : NSObject

#pragma mark Public

- (instancetype)init;

+ (void)mainWithNSStringArray:(IOSObjectArray *)args;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleLICENSE)

inline NSString *OrgSpongycastleLICENSE_get_licenseText(void);
inline NSString *OrgSpongycastleLICENSE_set_licenseText(NSString *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *OrgSpongycastleLICENSE_licenseText;
J2OBJC_STATIC_FIELD_OBJ(OrgSpongycastleLICENSE, licenseText, NSString *)

FOUNDATION_EXPORT void OrgSpongycastleLICENSE_init(OrgSpongycastleLICENSE *self);

FOUNDATION_EXPORT OrgSpongycastleLICENSE *new_OrgSpongycastleLICENSE_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleLICENSE *create_OrgSpongycastleLICENSE_init(void);

FOUNDATION_EXPORT void OrgSpongycastleLICENSE_mainWithNSStringArray_(IOSObjectArray *args);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleLICENSE)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleLICENSE")
