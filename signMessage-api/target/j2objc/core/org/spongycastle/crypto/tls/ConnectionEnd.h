//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/ConnectionEnd.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsConnectionEnd")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsConnectionEnd
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsConnectionEnd 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsConnectionEnd 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsConnectionEnd

#if !defined (OrgSpongycastleCryptoTlsConnectionEnd_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsConnectionEnd || defined(INCLUDE_OrgSpongycastleCryptoTlsConnectionEnd))
#define OrgSpongycastleCryptoTlsConnectionEnd_

@interface OrgSpongycastleCryptoTlsConnectionEnd : NSObject

#pragma mark Public

- (instancetype)init;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsConnectionEnd)

inline jint OrgSpongycastleCryptoTlsConnectionEnd_get_server(void);
#define OrgSpongycastleCryptoTlsConnectionEnd_server 0
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoTlsConnectionEnd, server, jint)

inline jint OrgSpongycastleCryptoTlsConnectionEnd_get_client(void);
#define OrgSpongycastleCryptoTlsConnectionEnd_client 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoTlsConnectionEnd, client, jint)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsConnectionEnd_init(OrgSpongycastleCryptoTlsConnectionEnd *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsConnectionEnd *new_OrgSpongycastleCryptoTlsConnectionEnd_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsConnectionEnd *create_OrgSpongycastleCryptoTlsConnectionEnd_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsConnectionEnd)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsConnectionEnd")
