//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/CFBBlockCipher.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoModesCFBBlockCipher")
#ifdef RESTRICT_OrgSpongycastleCryptoModesCFBBlockCipher
#define INCLUDE_ALL_OrgSpongycastleCryptoModesCFBBlockCipher 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoModesCFBBlockCipher 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoModesCFBBlockCipher

#if !defined (OrgSpongycastleCryptoModesCFBBlockCipher_) && (INCLUDE_ALL_OrgSpongycastleCryptoModesCFBBlockCipher || defined(INCLUDE_OrgSpongycastleCryptoModesCFBBlockCipher))
#define OrgSpongycastleCryptoModesCFBBlockCipher_

#define RESTRICT_OrgSpongycastleCryptoStreamBlockCipher 1
#define INCLUDE_OrgSpongycastleCryptoStreamBlockCipher 1
#include "org/spongycastle/crypto/StreamBlockCipher.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoBlockCipher;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoModesCFBBlockCipher : OrgSpongycastleCryptoStreamBlockCipher

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
                                                 withInt:(jint)bitBlockSize;

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (IOSByteArray *)getCurrentIV;

- (void)init__WithBoolean:(jboolean)encrypting
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

#pragma mark Protected

- (jbyte)calculateByteWithByte:(jbyte)inArg;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoModesCFBBlockCipher)

FOUNDATION_EXPORT void OrgSpongycastleCryptoModesCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withInt_(OrgSpongycastleCryptoModesCFBBlockCipher *self, id<OrgSpongycastleCryptoBlockCipher> cipher, jint bitBlockSize);

FOUNDATION_EXPORT OrgSpongycastleCryptoModesCFBBlockCipher *new_OrgSpongycastleCryptoModesCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withInt_(id<OrgSpongycastleCryptoBlockCipher> cipher, jint bitBlockSize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoModesCFBBlockCipher *create_OrgSpongycastleCryptoModesCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withInt_(id<OrgSpongycastleCryptoBlockCipher> cipher, jint bitBlockSize);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoModesCFBBlockCipher)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoModesCFBBlockCipher")
