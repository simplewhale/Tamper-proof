//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/MontgomeryLadderMultiplier.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcMontgomeryLadderMultiplier")
#ifdef RESTRICT_OrgSpongycastleMathEcMontgomeryLadderMultiplier
#define INCLUDE_ALL_OrgSpongycastleMathEcMontgomeryLadderMultiplier 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcMontgomeryLadderMultiplier 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcMontgomeryLadderMultiplier

#if !defined (OrgSpongycastleMathEcMontgomeryLadderMultiplier_) && (INCLUDE_ALL_OrgSpongycastleMathEcMontgomeryLadderMultiplier || defined(INCLUDE_OrgSpongycastleMathEcMontgomeryLadderMultiplier))
#define OrgSpongycastleMathEcMontgomeryLadderMultiplier_

#define RESTRICT_OrgSpongycastleMathEcAbstractECMultiplier 1
#define INCLUDE_OrgSpongycastleMathEcAbstractECMultiplier 1
#include "org/spongycastle/math/ec/AbstractECMultiplier.h"

@class JavaMathBigInteger;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcMontgomeryLadderMultiplier : OrgSpongycastleMathEcAbstractECMultiplier

#pragma mark Public

- (instancetype)init;

#pragma mark Protected

- (OrgSpongycastleMathEcECPoint *)multiplyPositiveWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)p
                                                            withJavaMathBigInteger:(JavaMathBigInteger *)k;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcMontgomeryLadderMultiplier)

FOUNDATION_EXPORT void OrgSpongycastleMathEcMontgomeryLadderMultiplier_init(OrgSpongycastleMathEcMontgomeryLadderMultiplier *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcMontgomeryLadderMultiplier *new_OrgSpongycastleMathEcMontgomeryLadderMultiplier_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcMontgomeryLadderMultiplier *create_OrgSpongycastleMathEcMontgomeryLadderMultiplier_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcMontgomeryLadderMultiplier)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcMontgomeryLadderMultiplier")