//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/ChaCha7539Engine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesChaCha7539Engine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesChaCha7539Engine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesChaCha7539Engine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesChaCha7539Engine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesChaCha7539Engine

#if !defined (OrgSpongycastleCryptoEnginesChaCha7539Engine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesChaCha7539Engine || defined(INCLUDE_OrgSpongycastleCryptoEnginesChaCha7539Engine))
#define OrgSpongycastleCryptoEnginesChaCha7539Engine_

#define RESTRICT_OrgSpongycastleCryptoEnginesSalsa20Engine 1
#define INCLUDE_OrgSpongycastleCryptoEnginesSalsa20Engine 1
#include "org/spongycastle/crypto/engines/Salsa20Engine.h"

@class IOSByteArray;

@interface OrgSpongycastleCryptoEnginesChaCha7539Engine : OrgSpongycastleCryptoEnginesSalsa20Engine

#pragma mark Public

- (instancetype)init;

- (NSString *)getAlgorithmName;

#pragma mark Protected

- (void)advanceCounter;

- (void)advanceCounterWithLong:(jlong)diff;

- (void)generateKeyStreamWithByteArray:(IOSByteArray *)output;

- (jlong)getCounter;

- (jint)getNonceSize;

- (void)resetCounter;

- (void)retreatCounter;

- (void)retreatCounterWithLong:(jlong)diff;

- (void)setKeyWithByteArray:(IOSByteArray *)keyBytes
              withByteArray:(IOSByteArray *)ivBytes;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEnginesChaCha7539Engine)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesChaCha7539Engine_init(OrgSpongycastleCryptoEnginesChaCha7539Engine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesChaCha7539Engine *new_OrgSpongycastleCryptoEnginesChaCha7539Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesChaCha7539Engine *create_OrgSpongycastleCryptoEnginesChaCha7539Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesChaCha7539Engine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesChaCha7539Engine")