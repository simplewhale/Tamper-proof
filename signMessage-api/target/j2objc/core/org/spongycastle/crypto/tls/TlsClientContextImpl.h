//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsClientContextImpl.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsClientContextImpl")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsClientContextImpl
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsClientContextImpl 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsClientContextImpl 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsClientContextImpl

#if !defined (OrgSpongycastleCryptoTlsTlsClientContextImpl_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsClientContextImpl || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsClientContextImpl))
#define OrgSpongycastleCryptoTlsTlsClientContextImpl_

#define RESTRICT_OrgSpongycastleCryptoTlsAbstractTlsContext 1
#define INCLUDE_OrgSpongycastleCryptoTlsAbstractTlsContext 1
#include "org/spongycastle/crypto/tls/AbstractTlsContext.h"

#define RESTRICT_OrgSpongycastleCryptoTlsTlsClientContext 1
#define INCLUDE_OrgSpongycastleCryptoTlsTlsClientContext 1
#include "org/spongycastle/crypto/tls/TlsClientContext.h"

@class JavaSecuritySecureRandom;
@class OrgSpongycastleCryptoTlsSecurityParameters;

@interface OrgSpongycastleCryptoTlsTlsClientContextImpl : OrgSpongycastleCryptoTlsAbstractTlsContext < OrgSpongycastleCryptoTlsTlsClientContext >

#pragma mark Public

- (jboolean)isServer;

#pragma mark Package-Private

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom
  withOrgSpongycastleCryptoTlsSecurityParameters:(OrgSpongycastleCryptoTlsSecurityParameters *)securityParameters;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsClientContextImpl)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsTlsClientContextImpl_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoTlsSecurityParameters_(OrgSpongycastleCryptoTlsTlsClientContextImpl *self, JavaSecuritySecureRandom *secureRandom, OrgSpongycastleCryptoTlsSecurityParameters *securityParameters);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsClientContextImpl *new_OrgSpongycastleCryptoTlsTlsClientContextImpl_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoTlsSecurityParameters_(JavaSecuritySecureRandom *secureRandom, OrgSpongycastleCryptoTlsSecurityParameters *securityParameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsClientContextImpl *create_OrgSpongycastleCryptoTlsTlsClientContextImpl_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoTlsSecurityParameters_(JavaSecuritySecureRandom *secureRandom, OrgSpongycastleCryptoTlsSecurityParameters *securityParameters);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsClientContextImpl)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsClientContextImpl")
