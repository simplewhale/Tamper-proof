//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/ARIAEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesARIAEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesARIAEngine

#if !defined (OrgSpongycastleCryptoEnginesARIAEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesARIAEngine))
#define OrgSpongycastleCryptoEnginesARIAEngine_

#define RESTRICT_OrgSpongycastleCryptoBlockCipher 1
#define INCLUDE_OrgSpongycastleCryptoBlockCipher 1
#include "org/spongycastle/crypto/BlockCipher.h"

@class IOSByteArray;
@class IOSObjectArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEnginesARIAEngine : NSObject < OrgSpongycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype)init;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

#pragma mark Protected

+ (void)AWithByteArray:(IOSByteArray *)z;

+ (void)FEWithByteArray:(IOSByteArray *)D
          withByteArray:(IOSByteArray *)RK;

+ (void)FOWithByteArray:(IOSByteArray *)D
          withByteArray:(IOSByteArray *)RK;

+ (IOSObjectArray *)keyScheduleWithBoolean:(jboolean)forEncryption
                             withByteArray:(IOSByteArray *)K;

+ (void)keyScheduleRoundWithByteArray:(IOSByteArray *)rk
                        withByteArray:(IOSByteArray *)w
                        withByteArray:(IOSByteArray *)wr
                              withInt:(jint)n;

+ (void)reverseKeysWithByteArray2:(IOSObjectArray *)keys;

+ (jbyte)SB1WithByte:(jbyte)x;

+ (jbyte)SB2WithByte:(jbyte)x;

+ (jbyte)SB3WithByte:(jbyte)x;

+ (jbyte)SB4WithByte:(jbyte)x;

+ (void)SL1WithByteArray:(IOSByteArray *)z;

+ (void)SL2WithByteArray:(IOSByteArray *)z;

+ (void)xor__WithByteArray:(IOSByteArray *)z
             withByteArray:(IOSByteArray *)x;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoEnginesARIAEngine)

inline jint OrgSpongycastleCryptoEnginesARIAEngine_get_BLOCK_SIZE(void);
#define OrgSpongycastleCryptoEnginesARIAEngine_BLOCK_SIZE 16
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoEnginesARIAEngine, BLOCK_SIZE, jint)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_init(OrgSpongycastleCryptoEnginesARIAEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesARIAEngine *new_OrgSpongycastleCryptoEnginesARIAEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesARIAEngine *create_OrgSpongycastleCryptoEnginesARIAEngine_init(void);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_AWithByteArray_(IOSByteArray *z);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_FEWithByteArray_withByteArray_(IOSByteArray *D, IOSByteArray *RK);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_FOWithByteArray_withByteArray_(IOSByteArray *D, IOSByteArray *RK);

FOUNDATION_EXPORT IOSObjectArray *OrgSpongycastleCryptoEnginesARIAEngine_keyScheduleWithBoolean_withByteArray_(jboolean forEncryption, IOSByteArray *K);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_keyScheduleRoundWithByteArray_withByteArray_withByteArray_withInt_(IOSByteArray *rk, IOSByteArray *w, IOSByteArray *wr, jint n);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_reverseKeysWithByteArray2_(IOSObjectArray *keys);

FOUNDATION_EXPORT jbyte OrgSpongycastleCryptoEnginesARIAEngine_SB1WithByte_(jbyte x);

FOUNDATION_EXPORT jbyte OrgSpongycastleCryptoEnginesARIAEngine_SB2WithByte_(jbyte x);

FOUNDATION_EXPORT jbyte OrgSpongycastleCryptoEnginesARIAEngine_SB3WithByte_(jbyte x);

FOUNDATION_EXPORT jbyte OrgSpongycastleCryptoEnginesARIAEngine_SB4WithByte_(jbyte x);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_SL1WithByteArray_(IOSByteArray *z);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_SL2WithByteArray_(IOSByteArray *z);

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAEngine_xor__WithByteArray_withByteArray_(IOSByteArray *z, IOSByteArray *x);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesARIAEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAEngine")
