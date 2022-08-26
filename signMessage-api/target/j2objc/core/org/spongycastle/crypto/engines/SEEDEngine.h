//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/SEEDEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesSEEDEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesSEEDEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesSEEDEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesSEEDEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesSEEDEngine

#if !defined (OrgSpongycastleCryptoEnginesSEEDEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesSEEDEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesSEEDEngine))
#define OrgSpongycastleCryptoEnginesSEEDEngine_

#define RESTRICT_OrgSpongycastleCryptoBlockCipher 1
#define INCLUDE_OrgSpongycastleCryptoBlockCipher 1
#include "org/spongycastle/crypto/BlockCipher.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEnginesSEEDEngine : NSObject < OrgSpongycastleCryptoBlockCipher >

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

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoEnginesSEEDEngine)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesSEEDEngine_init(OrgSpongycastleCryptoEnginesSEEDEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesSEEDEngine *new_OrgSpongycastleCryptoEnginesSEEDEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesSEEDEngine *create_OrgSpongycastleCryptoEnginesSEEDEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesSEEDEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesSEEDEngine")