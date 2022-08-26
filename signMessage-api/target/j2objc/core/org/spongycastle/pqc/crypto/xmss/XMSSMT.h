//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSMT.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMT")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSMT
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMT 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMT 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSMT

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSMT_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMT || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSMT))
#define OrgSpongycastlePqcCryptoXmssXMSSMT_

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class OrgSpongycastlePqcCryptoXmssXMSSMTParameters;
@class OrgSpongycastlePqcCryptoXmssXMSSParameters;

@interface OrgSpongycastlePqcCryptoXmssXMSSMT : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params
                                        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)prng;

- (IOSByteArray *)exportPrivateKey;

- (IOSByteArray *)exportPublicKey;

- (void)generateKeys;

- (OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)getParams;

- (IOSByteArray *)getPublicSeed;

- (void)importStateWithByteArray:(IOSByteArray *)privateKey
                   withByteArray:(IOSByteArray *)publicKey;

- (IOSByteArray *)signWithByteArray:(IOSByteArray *)message;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature
                           withByteArray:(IOSByteArray *)publicKey;

#pragma mark Protected

- (OrgSpongycastlePqcCryptoXmssXMSSParameters *)getXMSS;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSMT)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(OrgSpongycastlePqcCryptoXmssXMSSMT *self, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, JavaSecuritySecureRandom *prng);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSMT *new_OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, JavaSecuritySecureRandom *prng) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSMT *create_OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, JavaSecuritySecureRandom *prng);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSMT)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMT")
