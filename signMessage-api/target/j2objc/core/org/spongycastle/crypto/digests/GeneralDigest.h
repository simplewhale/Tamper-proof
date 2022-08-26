//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/GeneralDigest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsGeneralDigest")
#ifdef RESTRICT_OrgSpongycastleCryptoDigestsGeneralDigest
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsGeneralDigest 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoDigestsGeneralDigest 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoDigestsGeneralDigest

#if !defined (OrgSpongycastleCryptoDigestsGeneralDigest_) && (INCLUDE_ALL_OrgSpongycastleCryptoDigestsGeneralDigest || defined(INCLUDE_OrgSpongycastleCryptoDigestsGeneralDigest))
#define OrgSpongycastleCryptoDigestsGeneralDigest_

#define RESTRICT_OrgSpongycastleCryptoExtendedDigest 1
#define INCLUDE_OrgSpongycastleCryptoExtendedDigest 1
#include "org/spongycastle/crypto/ExtendedDigest.h"

#define RESTRICT_OrgSpongycastleUtilMemoable 1
#define INCLUDE_OrgSpongycastleUtilMemoable 1
#include "org/spongycastle/util/Memoable.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoDigestsGeneralDigest : NSObject < OrgSpongycastleCryptoExtendedDigest, OrgSpongycastleUtilMemoable >

#pragma mark Public

- (void)finish;

- (jint)getByteLength;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

#pragma mark Protected

- (instancetype)init;

- (instancetype)initWithByteArray:(IOSByteArray *)encodedState;

- (instancetype)initWithOrgSpongycastleCryptoDigestsGeneralDigest:(OrgSpongycastleCryptoDigestsGeneralDigest *)t;

- (void)copyInWithOrgSpongycastleCryptoDigestsGeneralDigest:(OrgSpongycastleCryptoDigestsGeneralDigest *)t OBJC_METHOD_FAMILY_NONE;

- (void)populateStateWithByteArray:(IOSByteArray *)state;

- (void)processBlock;

- (void)processLengthWithLong:(jlong)bitLength;

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoDigestsGeneralDigest)

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsGeneralDigest_init(OrgSpongycastleCryptoDigestsGeneralDigest *self);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsGeneralDigest_initWithOrgSpongycastleCryptoDigestsGeneralDigest_(OrgSpongycastleCryptoDigestsGeneralDigest *self, OrgSpongycastleCryptoDigestsGeneralDigest *t);

FOUNDATION_EXPORT void OrgSpongycastleCryptoDigestsGeneralDigest_initWithByteArray_(OrgSpongycastleCryptoDigestsGeneralDigest *self, IOSByteArray *encodedState);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoDigestsGeneralDigest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoDigestsGeneralDigest")