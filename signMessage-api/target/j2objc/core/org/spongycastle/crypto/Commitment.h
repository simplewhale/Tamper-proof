//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/Commitment.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoCommitment")
#ifdef RESTRICT_OrgSpongycastleCryptoCommitment
#define INCLUDE_ALL_OrgSpongycastleCryptoCommitment 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoCommitment 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoCommitment

#if !defined (OrgSpongycastleCryptoCommitment_) && (INCLUDE_ALL_OrgSpongycastleCryptoCommitment || defined(INCLUDE_OrgSpongycastleCryptoCommitment))
#define OrgSpongycastleCryptoCommitment_

@class IOSByteArray;

@interface OrgSpongycastleCryptoCommitment : NSObject

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)secret
                    withByteArray:(IOSByteArray *)commitment;

- (IOSByteArray *)getCommitment;

- (IOSByteArray *)getSecret;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoCommitment)

FOUNDATION_EXPORT void OrgSpongycastleCryptoCommitment_initWithByteArray_withByteArray_(OrgSpongycastleCryptoCommitment *self, IOSByteArray *secret, IOSByteArray *commitment);

FOUNDATION_EXPORT OrgSpongycastleCryptoCommitment *new_OrgSpongycastleCryptoCommitment_initWithByteArray_withByteArray_(IOSByteArray *secret, IOSByteArray *commitment) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoCommitment *create_OrgSpongycastleCryptoCommitment_initWithByteArray_withByteArray_(IOSByteArray *secret, IOSByteArray *commitment);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoCommitment)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoCommitment")
