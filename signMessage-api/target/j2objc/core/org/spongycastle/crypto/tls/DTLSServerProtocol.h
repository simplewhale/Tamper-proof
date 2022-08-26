//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/DTLSServerProtocol.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsDTLSServerProtocol")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsDTLSServerProtocol
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsDTLSServerProtocol 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsDTLSServerProtocol 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsDTLSServerProtocol

#if !defined (OrgSpongycastleCryptoTlsDTLSServerProtocol_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsDTLSServerProtocol || defined(INCLUDE_OrgSpongycastleCryptoTlsDTLSServerProtocol))
#define OrgSpongycastleCryptoTlsDTLSServerProtocol_

#define RESTRICT_OrgSpongycastleCryptoTlsDTLSProtocol 1
#define INCLUDE_OrgSpongycastleCryptoTlsDTLSProtocol 1
#include "org/spongycastle/crypto/tls/DTLSProtocol.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class OrgSpongycastleCryptoTlsCertificate;
@class OrgSpongycastleCryptoTlsCertificateRequest;
@class OrgSpongycastleCryptoTlsCertificateStatus;
@class OrgSpongycastleCryptoTlsDTLSRecordLayer;
@class OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState;
@class OrgSpongycastleCryptoTlsDTLSTransport;
@class OrgSpongycastleCryptoTlsNewSessionTicket;
@protocol OrgSpongycastleCryptoTlsDatagramTransport;
@protocol OrgSpongycastleCryptoTlsTlsHandshakeHash;
@protocol OrgSpongycastleCryptoTlsTlsServer;

@interface OrgSpongycastleCryptoTlsDTLSServerProtocol : OrgSpongycastleCryptoTlsDTLSProtocol {
 @public
  jboolean verifyRequests_;
}

#pragma mark Public

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

- (OrgSpongycastleCryptoTlsDTLSTransport *)acceptWithOrgSpongycastleCryptoTlsTlsServer:(id<OrgSpongycastleCryptoTlsTlsServer>)server
                                         withOrgSpongycastleCryptoTlsDatagramTransport:(id<OrgSpongycastleCryptoTlsDatagramTransport>)transport;

- (jboolean)getVerifyRequests;

- (void)setVerifyRequestsWithBoolean:(jboolean)verifyRequests;

#pragma mark Protected

- (void)abortServerHandshakeWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                    withOrgSpongycastleCryptoTlsDTLSRecordLayer:(OrgSpongycastleCryptoTlsDTLSRecordLayer *)recordLayer
                                                                                      withShort:(jshort)alertDescription;

- (jboolean)expectCertificateVerifyMessageWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state;

- (IOSByteArray *)generateCertificateRequestWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                 withOrgSpongycastleCryptoTlsCertificateRequest:(OrgSpongycastleCryptoTlsCertificateRequest *)certificateRequest;

- (IOSByteArray *)generateCertificateStatusWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                 withOrgSpongycastleCryptoTlsCertificateStatus:(OrgSpongycastleCryptoTlsCertificateStatus *)certificateStatus;

- (IOSByteArray *)generateNewSessionTicketWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                 withOrgSpongycastleCryptoTlsNewSessionTicket:(OrgSpongycastleCryptoTlsNewSessionTicket *)newSessionTicket;

- (IOSByteArray *)generateServerHelloWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state;

- (void)invalidateSessionWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state;

- (void)notifyClientCertificateWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                           withOrgSpongycastleCryptoTlsCertificate:(OrgSpongycastleCryptoTlsCertificate *)clientCertificate;

- (void)processCertificateVerifyWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                      withByteArray:(IOSByteArray *)body
                                                       withOrgSpongycastleCryptoTlsTlsHandshakeHash:(id<OrgSpongycastleCryptoTlsTlsHandshakeHash>)prepareFinishHash;

- (void)processClientCertificateWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                      withByteArray:(IOSByteArray *)body;

- (void)processClientHelloWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                withByteArray:(IOSByteArray *)body;

- (void)processClientKeyExchangeWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                      withByteArray:(IOSByteArray *)body;

- (void)processClientSupplementalDataWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                           withByteArray:(IOSByteArray *)body;

- (OrgSpongycastleCryptoTlsDTLSTransport *)serverHandshakeWithOrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                  withOrgSpongycastleCryptoTlsDTLSRecordLayer:(OrgSpongycastleCryptoTlsDTLSRecordLayer *)recordLayer;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsDTLSServerProtocol)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsDTLSServerProtocol_initWithJavaSecuritySecureRandom_(OrgSpongycastleCryptoTlsDTLSServerProtocol *self, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDTLSServerProtocol *new_OrgSpongycastleCryptoTlsDTLSServerProtocol_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *secureRandom) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDTLSServerProtocol *create_OrgSpongycastleCryptoTlsDTLSServerProtocol_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *secureRandom);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsDTLSServerProtocol)

#endif

#if !defined (OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsDTLSServerProtocol || defined(INCLUDE_OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState))
#define OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_

@class IOSIntArray;
@class IOSShortArray;
@class JavaUtilHashtable;
@class OrgSpongycastleCryptoTlsCertificate;
@class OrgSpongycastleCryptoTlsCertificateRequest;
@class OrgSpongycastleCryptoTlsSessionParameters;
@class OrgSpongycastleCryptoTlsSessionParameters_Builder;
@class OrgSpongycastleCryptoTlsTlsServerContextImpl;
@protocol OrgSpongycastleCryptoTlsTlsCredentials;
@protocol OrgSpongycastleCryptoTlsTlsKeyExchange;
@protocol OrgSpongycastleCryptoTlsTlsServer;
@protocol OrgSpongycastleCryptoTlsTlsSession;

@interface OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState : NSObject {
 @public
  id<OrgSpongycastleCryptoTlsTlsServer> server_;
  OrgSpongycastleCryptoTlsTlsServerContextImpl *serverContext_;
  id<OrgSpongycastleCryptoTlsTlsSession> tlsSession_;
  OrgSpongycastleCryptoTlsSessionParameters *sessionParameters_;
  OrgSpongycastleCryptoTlsSessionParameters_Builder *sessionParametersBuilder_;
  IOSIntArray *offeredCipherSuites_;
  IOSShortArray *offeredCompressionMethods_;
  JavaUtilHashtable *clientExtensions_;
  JavaUtilHashtable *serverExtensions_;
  jboolean resumedSession_;
  jboolean secure_renegotiation_;
  jboolean allowCertificateStatus_;
  jboolean expectSessionTicket_;
  id<OrgSpongycastleCryptoTlsTlsKeyExchange> keyExchange_;
  id<OrgSpongycastleCryptoTlsTlsCredentials> serverCredentials_;
  OrgSpongycastleCryptoTlsCertificateRequest *certificateRequest_;
  jshort clientCertificateType_;
  OrgSpongycastleCryptoTlsCertificate *clientCertificate_;
}

#pragma mark Protected

- (instancetype)init;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, server_, id<OrgSpongycastleCryptoTlsTlsServer>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, serverContext_, OrgSpongycastleCryptoTlsTlsServerContextImpl *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, tlsSession_, id<OrgSpongycastleCryptoTlsTlsSession>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, sessionParameters_, OrgSpongycastleCryptoTlsSessionParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, sessionParametersBuilder_, OrgSpongycastleCryptoTlsSessionParameters_Builder *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, offeredCipherSuites_, IOSIntArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, offeredCompressionMethods_, IOSShortArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, clientExtensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, serverExtensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, keyExchange_, id<OrgSpongycastleCryptoTlsTlsKeyExchange>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, serverCredentials_, id<OrgSpongycastleCryptoTlsTlsCredentials>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, certificateRequest_, OrgSpongycastleCryptoTlsCertificateRequest *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, clientCertificate_, OrgSpongycastleCryptoTlsCertificate *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_init(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *new_OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *create_OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsDTLSServerProtocol")