//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSSigner.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSSigner")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSSigner
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSSigner 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSSigner 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSSigner

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSSigner_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSSigner || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSSigner))
#define OrgSpongycastlePqcCryptoXmssXMSSSigner_

#define RESTRICT_OrgSpongycastlePqcCryptoStateAwareMessageSigner 1
#define INCLUDE_OrgSpongycastlePqcCryptoStateAwareMessageSigner 1
#include "org/spongycastle/pqc/crypto/StateAwareMessageSigner.h"

@class IOSByteArray;
@class OrgSpongycastleCryptoParamsAsymmetricKeyParameter;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastlePqcCryptoXmssXMSSSigner : NSObject < OrgSpongycastlePqcCryptoStateAwareMessageSigner >

#pragma mark Public

- (instancetype)init;

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)getUpdatedPrivateKey;

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSSigner)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoXmssXMSSSigner_init(OrgSpongycastlePqcCryptoXmssXMSSSigner *self);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSSigner *new_OrgSpongycastlePqcCryptoXmssXMSSSigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSSigner *create_OrgSpongycastlePqcCryptoXmssXMSSSigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSSigner)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSSigner")