//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/ec/ECPair.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEcECPair")
#ifdef RESTRICT_OrgSpongycastleCryptoEcECPair
#define INCLUDE_ALL_OrgSpongycastleCryptoEcECPair 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEcECPair 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEcECPair

#if !defined (OrgSpongycastleCryptoEcECPair_) && (INCLUDE_ALL_OrgSpongycastleCryptoEcECPair || defined(INCLUDE_OrgSpongycastleCryptoEcECPair))
#define OrgSpongycastleCryptoEcECPair_

@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleCryptoEcECPair : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)x
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)y;

- (jboolean)equalsWithOrgSpongycastleCryptoEcECPair:(OrgSpongycastleCryptoEcECPair *)other;

- (jboolean)isEqual:(id)other;

- (OrgSpongycastleMathEcECPoint *)getX;

- (OrgSpongycastleMathEcECPoint *)getY;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEcECPair)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEcECPair_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleMathEcECPoint_(OrgSpongycastleCryptoEcECPair *self, OrgSpongycastleMathEcECPoint *x, OrgSpongycastleMathEcECPoint *y);

FOUNDATION_EXPORT OrgSpongycastleCryptoEcECPair *new_OrgSpongycastleCryptoEcECPair_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleMathEcECPoint_(OrgSpongycastleMathEcECPoint *x, OrgSpongycastleMathEcECPoint *y) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEcECPair *create_OrgSpongycastleCryptoEcECPair_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleMathEcECPoint_(OrgSpongycastleMathEcECPoint *x, OrgSpongycastleMathEcECPoint *y);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEcECPair)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEcECPair")