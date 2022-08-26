//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/TEAEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesTEAEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesTEAEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesTEAEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesTEAEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesTEAEngine

#if !defined (OrgSpongycastleCryptoEnginesTEAEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesTEAEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesTEAEngine))
#define OrgSpongycastleCryptoEnginesTEAEngine_

#define RESTRICT_OrgSpongycastleCryptoBlockCipher 1
#define INCLUDE_OrgSpongycastleCryptoBlockCipher 1
#include "org/spongycastle/crypto/BlockCipher.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEnginesTEAEngine : NSObject < OrgSpongycastleCryptoBlockCipher >

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

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEnginesTEAEngine)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesTEAEngine_init(OrgSpongycastleCryptoEnginesTEAEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesTEAEngine *new_OrgSpongycastleCryptoEnginesTEAEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesTEAEngine *create_OrgSpongycastleCryptoEnginesTEAEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesTEAEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesTEAEngine")
