//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsDSSSigner.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsDSSSigner")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsDSSSigner
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsDSSSigner 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsDSSSigner 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsDSSSigner

#if !defined (OrgSpongycastleCryptoTlsTlsDSSSigner_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsDSSSigner || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsDSSSigner))
#define OrgSpongycastleCryptoTlsTlsDSSSigner_

#define RESTRICT_OrgSpongycastleCryptoTlsTlsDSASigner 1
#define INCLUDE_OrgSpongycastleCryptoTlsTlsDSASigner 1
#include "org/spongycastle/crypto/tls/TlsDSASigner.h"

@class OrgSpongycastleCryptoParamsAsymmetricKeyParameter;
@protocol OrgSpongycastleCryptoDSA;

@interface OrgSpongycastleCryptoTlsTlsDSSSigner : OrgSpongycastleCryptoTlsTlsDSASigner

#pragma mark Public

- (instancetype)init;

- (jboolean)isValidPublicKeyWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

#pragma mark Protected

- (id<OrgSpongycastleCryptoDSA>)createDSAImplWithShort:(jshort)hashAlgorithm;

- (jshort)getSignatureAlgorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsDSSSigner)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsTlsDSSSigner_init(OrgSpongycastleCryptoTlsTlsDSSSigner *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsDSSSigner *new_OrgSpongycastleCryptoTlsTlsDSSSigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsDSSSigner *create_OrgSpongycastleCryptoTlsTlsDSSSigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsDSSSigner)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsDSSSigner")