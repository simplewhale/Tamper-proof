//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/SimulatedTlsSRPIdentityManager.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager

#if !defined (OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager || defined(INCLUDE_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager))
#define OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager_

#define RESTRICT_OrgSpongycastleCryptoTlsTlsSRPIdentityManager 1
#define INCLUDE_OrgSpongycastleCryptoTlsTlsSRPIdentityManager 1
#include "org/spongycastle/crypto/tls/TlsSRPIdentityManager.h"

@class IOSByteArray;
@class OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator;
@class OrgSpongycastleCryptoParamsSRP6GroupParameters;
@class OrgSpongycastleCryptoTlsTlsSRPLoginParameters;
@protocol OrgSpongycastleCryptoMac;

@interface OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager : NSObject < OrgSpongycastleCryptoTlsTlsSRPIdentityManager > {
 @public
  OrgSpongycastleCryptoParamsSRP6GroupParameters *group_;
  OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator *verifierGenerator_;
  id<OrgSpongycastleCryptoMac> mac_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *)group
            withOrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator:(OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator *)verifierGenerator
                                          withOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)mac;

- (OrgSpongycastleCryptoTlsTlsSRPLoginParameters *)getLoginParametersWithByteArray:(IOSByteArray *)identity;

+ (OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager *)getRFC5054DefaultWithOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *)group
                                                                                                                  withByteArray:(IOSByteArray *)seedKey;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager, group_, OrgSpongycastleCryptoParamsSRP6GroupParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager, verifierGenerator_, OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager, mac_, id<OrgSpongycastleCryptoMac>)

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager *OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager_getRFC5054DefaultWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withByteArray_(OrgSpongycastleCryptoParamsSRP6GroupParameters *group, IOSByteArray *seedKey);

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withOrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator_withOrgSpongycastleCryptoMac_(OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager *self, OrgSpongycastleCryptoParamsSRP6GroupParameters *group, OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator *verifierGenerator, id<OrgSpongycastleCryptoMac> mac);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager *new_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withOrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator_withOrgSpongycastleCryptoMac_(OrgSpongycastleCryptoParamsSRP6GroupParameters *group, OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator *verifierGenerator, id<OrgSpongycastleCryptoMac> mac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager *create_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withOrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator_withOrgSpongycastleCryptoMac_(OrgSpongycastleCryptoParamsSRP6GroupParameters *group, OrgSpongycastleCryptoAgreementSrpSRP6VerifierGenerator *verifierGenerator, id<OrgSpongycastleCryptoMac> mac);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsSimulatedTlsSRPIdentityManager")
