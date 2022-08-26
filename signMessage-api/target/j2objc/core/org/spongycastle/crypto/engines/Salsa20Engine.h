//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/Salsa20Engine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesSalsa20Engine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesSalsa20Engine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesSalsa20Engine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesSalsa20Engine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesSalsa20Engine

#if !defined (OrgSpongycastleCryptoEnginesSalsa20Engine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesSalsa20Engine || defined(INCLUDE_OrgSpongycastleCryptoEnginesSalsa20Engine))
#define OrgSpongycastleCryptoEnginesSalsa20Engine_

#define RESTRICT_OrgSpongycastleCryptoSkippingStreamCipher 1
#define INCLUDE_OrgSpongycastleCryptoSkippingStreamCipher 1
#include "org/spongycastle/crypto/SkippingStreamCipher.h"

@class IOSByteArray;
@class IOSIntArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEnginesSalsa20Engine : NSObject < OrgSpongycastleCryptoSkippingStreamCipher > {
 @public
  jint rounds_;
  IOSIntArray *engineState_;
  IOSIntArray *x_;
}

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithInt:(jint)rounds;

- (NSString *)getAlgorithmName;

- (jlong)getPosition;

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

- (jbyte)returnByteWithByte:(jbyte)inArg;

+ (void)salsaCoreWithInt:(jint)rounds
            withIntArray:(IOSIntArray *)input
            withIntArray:(IOSIntArray *)x;

- (jlong)seekToWithLong:(jlong)position;

- (jlong)skipWithLong:(jlong)numberOfBytes;

#pragma mark Protected

- (void)advanceCounter;

- (void)advanceCounterWithLong:(jlong)diff;

- (void)generateKeyStreamWithByteArray:(IOSByteArray *)output;

- (jlong)getCounter;

- (jint)getNonceSize;

- (void)packTauOrSigmaWithInt:(jint)keyLength
                 withIntArray:(IOSIntArray *)state
                      withInt:(jint)stateOffset;

- (void)resetCounter;

- (void)retreatCounter;

- (void)retreatCounterWithLong:(jlong)diff;

+ (jint)rotlWithInt:(jint)x
            withInt:(jint)y;

- (void)setKeyWithByteArray:(IOSByteArray *)keyBytes
              withByteArray:(IOSByteArray *)ivBytes;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoEnginesSalsa20Engine)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesSalsa20Engine, engineState_, IOSIntArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesSalsa20Engine, x_, IOSIntArray *)

inline jint OrgSpongycastleCryptoEnginesSalsa20Engine_get_DEFAULT_ROUNDS(void);
#define OrgSpongycastleCryptoEnginesSalsa20Engine_DEFAULT_ROUNDS 20
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoEnginesSalsa20Engine, DEFAULT_ROUNDS, jint)

inline IOSByteArray *OrgSpongycastleCryptoEnginesSalsa20Engine_get_sigma(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleCryptoEnginesSalsa20Engine_sigma;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoEnginesSalsa20Engine, sigma, IOSByteArray *)

inline IOSByteArray *OrgSpongycastleCryptoEnginesSalsa20Engine_get_tau(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleCryptoEnginesSalsa20Engine_tau;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoEnginesSalsa20Engine, tau, IOSByteArray *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesSalsa20Engine_init(OrgSpongycastleCryptoEnginesSalsa20Engine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesSalsa20Engine *new_OrgSpongycastleCryptoEnginesSalsa20Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesSalsa20Engine *create_OrgSpongycastleCryptoEnginesSalsa20Engine_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(OrgSpongycastleCryptoEnginesSalsa20Engine *self, jint rounds);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesSalsa20Engine *new_OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(jint rounds) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesSalsa20Engine *create_OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(jint rounds);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesSalsa20Engine_salsaCoreWithInt_withIntArray_withIntArray_(jint rounds, IOSIntArray *input, IOSIntArray *x);

FOUNDATION_EXPORT jint OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(jint x, jint y);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesSalsa20Engine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesSalsa20Engine")
