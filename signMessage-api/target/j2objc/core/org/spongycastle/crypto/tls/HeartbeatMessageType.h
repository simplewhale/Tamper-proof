//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/HeartbeatMessageType.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsHeartbeatMessageType")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsHeartbeatMessageType
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsHeartbeatMessageType 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsHeartbeatMessageType 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsHeartbeatMessageType

#if !defined (OrgSpongycastleCryptoTlsHeartbeatMessageType_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsHeartbeatMessageType || defined(INCLUDE_OrgSpongycastleCryptoTlsHeartbeatMessageType))
#define OrgSpongycastleCryptoTlsHeartbeatMessageType_

@interface OrgSpongycastleCryptoTlsHeartbeatMessageType : NSObject

#pragma mark Public

- (instancetype)init;

+ (jboolean)isValidWithShort:(jshort)heartbeatMessageType;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsHeartbeatMessageType)

inline jshort OrgSpongycastleCryptoTlsHeartbeatMessageType_get_heartbeat_request(void);
#define OrgSpongycastleCryptoTlsHeartbeatMessageType_heartbeat_request 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoTlsHeartbeatMessageType, heartbeat_request, jshort)

inline jshort OrgSpongycastleCryptoTlsHeartbeatMessageType_get_heartbeat_response(void);
#define OrgSpongycastleCryptoTlsHeartbeatMessageType_heartbeat_response 2
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoTlsHeartbeatMessageType, heartbeat_response, jshort)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsHeartbeatMessageType_init(OrgSpongycastleCryptoTlsHeartbeatMessageType *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsHeartbeatMessageType *new_OrgSpongycastleCryptoTlsHeartbeatMessageType_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsHeartbeatMessageType *create_OrgSpongycastleCryptoTlsHeartbeatMessageType_init(void);

FOUNDATION_EXPORT jboolean OrgSpongycastleCryptoTlsHeartbeatMessageType_isValidWithShort_(jshort heartbeatMessageType);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsHeartbeatMessageType)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsHeartbeatMessageType")