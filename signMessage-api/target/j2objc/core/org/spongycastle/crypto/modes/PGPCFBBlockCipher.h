//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/PGPCFBBlockCipher.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoModesPGPCFBBlockCipher")
#ifdef RESTRICT_OrgSpongycastleCryptoModesPGPCFBBlockCipher
#define INCLUDE_ALL_OrgSpongycastleCryptoModesPGPCFBBlockCipher 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoModesPGPCFBBlockCipher 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoModesPGPCFBBlockCipher

#if !defined (OrgSpongycastleCryptoModesPGPCFBBlockCipher_) && (INCLUDE_ALL_OrgSpongycastleCryptoModesPGPCFBBlockCipher || defined(INCLUDE_OrgSpongycastleCryptoModesPGPCFBBlockCipher))
#define OrgSpongycastleCryptoModesPGPCFBBlockCipher_

#define RESTRICT_OrgSpongycastleCryptoBlockCipher 1
#define INCLUDE_OrgSpongycastleCryptoBlockCipher 1
#include "org/spongycastle/crypto/BlockCipher.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoModesPGPCFBBlockCipher : NSObject < OrgSpongycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
                                             withBoolean:(jboolean)inlineIv;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (id<OrgSpongycastleCryptoBlockCipher>)getUnderlyingCipher;

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoModesPGPCFBBlockCipher)

FOUNDATION_EXPORT void OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, id<OrgSpongycastleCryptoBlockCipher> cipher, jboolean inlineIv);

FOUNDATION_EXPORT OrgSpongycastleCryptoModesPGPCFBBlockCipher *new_OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(id<OrgSpongycastleCryptoBlockCipher> cipher, jboolean inlineIv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoModesPGPCFBBlockCipher *create_OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(id<OrgSpongycastleCryptoBlockCipher> cipher, jboolean inlineIv);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoModesPGPCFBBlockCipher)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoModesPGPCFBBlockCipher")
