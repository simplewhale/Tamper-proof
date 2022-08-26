//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/ISAACEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesISAACEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesISAACEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesISAACEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesISAACEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesISAACEngine

#if !defined (OrgSpongycastleCryptoEnginesISAACEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesISAACEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesISAACEngine))
#define OrgSpongycastleCryptoEnginesISAACEngine_

#define RESTRICT_OrgSpongycastleCryptoStreamCipher 1
#define INCLUDE_OrgSpongycastleCryptoStreamCipher 1
#include "org/spongycastle/crypto/StreamCipher.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEnginesISAACEngine : NSObject < OrgSpongycastleCryptoStreamCipher >

#pragma mark Public

- (instancetype)init;

- (NSString *)getAlgorithmName;

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

- (jbyte)returnByteWithByte:(jbyte)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEnginesISAACEngine)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesISAACEngine_init(OrgSpongycastleCryptoEnginesISAACEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesISAACEngine *new_OrgSpongycastleCryptoEnginesISAACEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesISAACEngine *create_OrgSpongycastleCryptoEnginesISAACEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesISAACEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesISAACEngine")