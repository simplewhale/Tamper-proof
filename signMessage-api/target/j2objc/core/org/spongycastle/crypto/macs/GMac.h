//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/macs/GMac.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoMacsGMac")
#ifdef RESTRICT_OrgSpongycastleCryptoMacsGMac
#define INCLUDE_ALL_OrgSpongycastleCryptoMacsGMac 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoMacsGMac 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoMacsGMac

#if !defined (OrgSpongycastleCryptoMacsGMac_) && (INCLUDE_ALL_OrgSpongycastleCryptoMacsGMac || defined(INCLUDE_OrgSpongycastleCryptoMacsGMac))
#define OrgSpongycastleCryptoMacsGMac_

#define RESTRICT_OrgSpongycastleCryptoMac 1
#define INCLUDE_OrgSpongycastleCryptoMac 1
#include "org/spongycastle/crypto/Mac.h"

@class IOSByteArray;
@class OrgSpongycastleCryptoModesGCMBlockCipher;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoMacsGMac : NSObject < OrgSpongycastleCryptoMac >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoModesGCMBlockCipher:(OrgSpongycastleCryptoModesGCMBlockCipher *)cipher;

- (instancetype)initWithOrgSpongycastleCryptoModesGCMBlockCipher:(OrgSpongycastleCryptoModesGCMBlockCipher *)cipher
                                                         withInt:(jint)macSizeBits;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getMacSize;

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoMacsGMac)

FOUNDATION_EXPORT void OrgSpongycastleCryptoMacsGMac_initWithOrgSpongycastleCryptoModesGCMBlockCipher_(OrgSpongycastleCryptoMacsGMac *self, OrgSpongycastleCryptoModesGCMBlockCipher *cipher);

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsGMac *new_OrgSpongycastleCryptoMacsGMac_initWithOrgSpongycastleCryptoModesGCMBlockCipher_(OrgSpongycastleCryptoModesGCMBlockCipher *cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsGMac *create_OrgSpongycastleCryptoMacsGMac_initWithOrgSpongycastleCryptoModesGCMBlockCipher_(OrgSpongycastleCryptoModesGCMBlockCipher *cipher);

FOUNDATION_EXPORT void OrgSpongycastleCryptoMacsGMac_initWithOrgSpongycastleCryptoModesGCMBlockCipher_withInt_(OrgSpongycastleCryptoMacsGMac *self, OrgSpongycastleCryptoModesGCMBlockCipher *cipher, jint macSizeBits);

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsGMac *new_OrgSpongycastleCryptoMacsGMac_initWithOrgSpongycastleCryptoModesGCMBlockCipher_withInt_(OrgSpongycastleCryptoModesGCMBlockCipher *cipher, jint macSizeBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsGMac *create_OrgSpongycastleCryptoMacsGMac_initWithOrgSpongycastleCryptoModesGCMBlockCipher_withInt_(OrgSpongycastleCryptoModesGCMBlockCipher *cipher, jint macSizeBits);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoMacsGMac)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoMacsGMac")
