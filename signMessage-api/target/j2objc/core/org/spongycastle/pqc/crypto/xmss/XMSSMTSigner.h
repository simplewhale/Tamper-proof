//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSMTSigner.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSigner")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSMTSigner
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSigner 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSigner 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSMTSigner

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSMTSigner_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSigner || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSMTSigner))
#define OrgSpongycastlePqcCryptoXmssXMSSMTSigner_

#define RESTRICT_OrgSpongycastlePqcCryptoStateAwareMessageSigner 1
#define INCLUDE_OrgSpongycastlePqcCryptoStateAwareMessageSigner 1
#include "org/spongycastle/pqc/crypto/StateAwareMessageSigner.h"

@class IOSByteArray;
@class OrgSpongycastleCryptoParamsAsymmetricKeyParameter;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastlePqcCryptoXmssXMSSMTSigner : NSObject < OrgSpongycastlePqcCryptoStateAwareMessageSigner >

#pragma mark Public

- (instancetype)init;

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)getUpdatedPrivateKey;

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSMTSigner)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoXmssXMSSMTSigner_init(OrgSpongycastlePqcCryptoXmssXMSSMTSigner *self);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSMTSigner *new_OrgSpongycastlePqcCryptoXmssXMSSMTSigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSMTSigner *create_OrgSpongycastlePqcCryptoXmssXMSSMTSigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSMTSigner)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSigner")
