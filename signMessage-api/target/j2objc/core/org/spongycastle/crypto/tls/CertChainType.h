//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/CertChainType.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsCertChainType")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsCertChainType
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsCertChainType 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsCertChainType 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsCertChainType

#if !defined (OrgSpongycastleCryptoTlsCertChainType_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsCertChainType || defined(INCLUDE_OrgSpongycastleCryptoTlsCertChainType))
#define OrgSpongycastleCryptoTlsCertChainType_

@interface OrgSpongycastleCryptoTlsCertChainType : NSObject

#pragma mark Public

- (instancetype)init;

+ (jboolean)isValidWithShort:(jshort)certChainType;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsCertChainType)

inline jshort OrgSpongycastleCryptoTlsCertChainType_get_individual_certs(void);
#define OrgSpongycastleCryptoTlsCertChainType_individual_certs 0
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoTlsCertChainType, individual_certs, jshort)

inline jshort OrgSpongycastleCryptoTlsCertChainType_get_pkipath(void);
#define OrgSpongycastleCryptoTlsCertChainType_pkipath 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoTlsCertChainType, pkipath, jshort)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsCertChainType_init(OrgSpongycastleCryptoTlsCertChainType *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsCertChainType *new_OrgSpongycastleCryptoTlsCertChainType_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsCertChainType *create_OrgSpongycastleCryptoTlsCertChainType_init(void);

FOUNDATION_EXPORT jboolean OrgSpongycastleCryptoTlsCertChainType_isValidWithShort_(jshort certChainType);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsCertChainType)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsCertChainType")
