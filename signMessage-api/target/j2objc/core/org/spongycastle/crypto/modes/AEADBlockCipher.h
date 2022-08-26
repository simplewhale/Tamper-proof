//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/AEADBlockCipher.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoModesAEADBlockCipher")
#ifdef RESTRICT_OrgSpongycastleCryptoModesAEADBlockCipher
#define INCLUDE_ALL_OrgSpongycastleCryptoModesAEADBlockCipher 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoModesAEADBlockCipher 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoModesAEADBlockCipher

#if !defined (OrgSpongycastleCryptoModesAEADBlockCipher_) && (INCLUDE_ALL_OrgSpongycastleCryptoModesAEADBlockCipher || defined(INCLUDE_OrgSpongycastleCryptoModesAEADBlockCipher))
#define OrgSpongycastleCryptoModesAEADBlockCipher_

@class IOSByteArray;
@protocol OrgSpongycastleCryptoBlockCipher;
@protocol OrgSpongycastleCryptoCipherParameters;

@protocol OrgSpongycastleCryptoModesAEADBlockCipher < JavaObject >

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (NSString *)getAlgorithmName;

- (id<OrgSpongycastleCryptoBlockCipher>)getUnderlyingCipher;

- (void)processAADByteWithByte:(jbyte)inArg;

- (void)processAADBytesWithByteArray:(IOSByteArray *)inArg
                             withInt:(jint)inOff
                             withInt:(jint)len;

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (IOSByteArray *)getMac;

- (jint)getUpdateOutputSizeWithInt:(jint)len;

- (jint)getOutputSizeWithInt:(jint)len;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoModesAEADBlockCipher)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoModesAEADBlockCipher)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoModesAEADBlockCipher")
