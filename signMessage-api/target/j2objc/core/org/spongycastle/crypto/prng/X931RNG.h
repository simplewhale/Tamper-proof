//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/X931RNG.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngX931RNG")
#ifdef RESTRICT_OrgSpongycastleCryptoPrngX931RNG
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngX931RNG 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngX931RNG 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPrngX931RNG

#if !defined (OrgSpongycastleCryptoPrngX931RNG_) && (INCLUDE_ALL_OrgSpongycastleCryptoPrngX931RNG || defined(INCLUDE_OrgSpongycastleCryptoPrngX931RNG))
#define OrgSpongycastleCryptoPrngX931RNG_

@class IOSByteArray;
@protocol OrgSpongycastleCryptoBlockCipher;
@protocol OrgSpongycastleCryptoPrngEntropySource;

@interface OrgSpongycastleCryptoPrngX931RNG : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)engine
                                           withByteArray:(IOSByteArray *)dateTimeVector
              withOrgSpongycastleCryptoPrngEntropySource:(id<OrgSpongycastleCryptoPrngEntropySource>)entropySource;

#pragma mark Package-Private

- (jint)generateWithByteArray:(IOSByteArray *)output
                  withBoolean:(jboolean)predictionResistant;

- (id<OrgSpongycastleCryptoPrngEntropySource>)getEntropySource;

- (void)reseed;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPrngX931RNG)

FOUNDATION_EXPORT void OrgSpongycastleCryptoPrngX931RNG_initWithOrgSpongycastleCryptoBlockCipher_withByteArray_withOrgSpongycastleCryptoPrngEntropySource_(OrgSpongycastleCryptoPrngX931RNG *self, id<OrgSpongycastleCryptoBlockCipher> engine, IOSByteArray *dateTimeVector, id<OrgSpongycastleCryptoPrngEntropySource> entropySource);

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngX931RNG *new_OrgSpongycastleCryptoPrngX931RNG_initWithOrgSpongycastleCryptoBlockCipher_withByteArray_withOrgSpongycastleCryptoPrngEntropySource_(id<OrgSpongycastleCryptoBlockCipher> engine, IOSByteArray *dateTimeVector, id<OrgSpongycastleCryptoPrngEntropySource> entropySource) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPrngX931RNG *create_OrgSpongycastleCryptoPrngX931RNG_initWithOrgSpongycastleCryptoBlockCipher_withByteArray_withOrgSpongycastleCryptoPrngEntropySource_(id<OrgSpongycastleCryptoBlockCipher> engine, IOSByteArray *dateTimeVector, id<OrgSpongycastleCryptoPrngEntropySource> entropySource);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPrngX931RNG)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngX931RNG")
