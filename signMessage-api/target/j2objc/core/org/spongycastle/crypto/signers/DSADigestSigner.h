//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/signers/DSADigestSigner.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoSignersDSADigestSigner")
#ifdef RESTRICT_OrgSpongycastleCryptoSignersDSADigestSigner
#define INCLUDE_ALL_OrgSpongycastleCryptoSignersDSADigestSigner 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoSignersDSADigestSigner 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoSignersDSADigestSigner

#if !defined (OrgSpongycastleCryptoSignersDSADigestSigner_) && (INCLUDE_ALL_OrgSpongycastleCryptoSignersDSADigestSigner || defined(INCLUDE_OrgSpongycastleCryptoSignersDSADigestSigner))
#define OrgSpongycastleCryptoSignersDSADigestSigner_

#define RESTRICT_OrgSpongycastleCryptoSigner 1
#define INCLUDE_OrgSpongycastleCryptoSigner 1
#include "org/spongycastle/crypto/Signer.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;
@protocol OrgSpongycastleCryptoDSA;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastleCryptoSignersDSADigestSigner : NSObject < OrgSpongycastleCryptoSigner >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoDSA:(id<OrgSpongycastleCryptoDSA>)signer
                 withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

- (IOSByteArray *)generateSignature;

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)input;

- (void)updateWithByteArray:(IOSByteArray *)input
                    withInt:(jint)inOff
                    withInt:(jint)length;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoSignersDSADigestSigner)

FOUNDATION_EXPORT void OrgSpongycastleCryptoSignersDSADigestSigner_initWithOrgSpongycastleCryptoDSA_withOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoSignersDSADigestSigner *self, id<OrgSpongycastleCryptoDSA> signer, id<OrgSpongycastleCryptoDigest> digest);

FOUNDATION_EXPORT OrgSpongycastleCryptoSignersDSADigestSigner *new_OrgSpongycastleCryptoSignersDSADigestSigner_initWithOrgSpongycastleCryptoDSA_withOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDSA> signer, id<OrgSpongycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoSignersDSADigestSigner *create_OrgSpongycastleCryptoSignersDSADigestSigner_initWithOrgSpongycastleCryptoDSA_withOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDSA> signer, id<OrgSpongycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoSignersDSADigestSigner)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoSignersDSADigestSigner")
