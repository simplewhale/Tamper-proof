//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/drbg/SP80090DRBG.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgSP80090DRBG")
#ifdef RESTRICT_OrgSpongycastleCryptoPrngDrbgSP80090DRBG
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgSP80090DRBG 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgSP80090DRBG 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPrngDrbgSP80090DRBG

#if !defined (OrgSpongycastleCryptoPrngDrbgSP80090DRBG_) && (INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgSP80090DRBG || defined(INCLUDE_OrgSpongycastleCryptoPrngDrbgSP80090DRBG))
#define OrgSpongycastleCryptoPrngDrbgSP80090DRBG_

@class IOSByteArray;

@protocol OrgSpongycastleCryptoPrngDrbgSP80090DRBG < JavaObject >

- (jint)getBlockSize;

- (jint)generateWithByteArray:(IOSByteArray *)output
                withByteArray:(IOSByteArray *)additionalInput
                  withBoolean:(jboolean)predictionResistant;

- (void)reseedWithByteArray:(IOSByteArray *)additionalInput;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPrngDrbgSP80090DRBG)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPrngDrbgSP80090DRBG)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPrngDrbgSP80090DRBG")
