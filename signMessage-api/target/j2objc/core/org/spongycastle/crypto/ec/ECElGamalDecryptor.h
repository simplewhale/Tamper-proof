//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/ec/ECElGamalDecryptor.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalDecryptor")
#ifdef RESTRICT_OrgSpongycastleCryptoEcECElGamalDecryptor
#define INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalDecryptor 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalDecryptor 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEcECElGamalDecryptor

#if !defined (OrgSpongycastleCryptoEcECElGamalDecryptor_) && (INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalDecryptor || defined(INCLUDE_OrgSpongycastleCryptoEcECElGamalDecryptor))
#define OrgSpongycastleCryptoEcECElGamalDecryptor_

#define RESTRICT_OrgSpongycastleCryptoEcECDecryptor 1
#define INCLUDE_OrgSpongycastleCryptoEcECDecryptor 1
#include "org/spongycastle/crypto/ec/ECDecryptor.h"

@class OrgSpongycastleCryptoEcECPair;
@class OrgSpongycastleMathEcECPoint;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEcECElGamalDecryptor : NSObject < OrgSpongycastleCryptoEcECDecryptor >

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleMathEcECPoint *)decryptWithOrgSpongycastleCryptoEcECPair:(OrgSpongycastleCryptoEcECPair *)pair;

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEcECElGamalDecryptor)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEcECElGamalDecryptor_init(OrgSpongycastleCryptoEcECElGamalDecryptor *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEcECElGamalDecryptor *new_OrgSpongycastleCryptoEcECElGamalDecryptor_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEcECElGamalDecryptor *create_OrgSpongycastleCryptoEcECElGamalDecryptor_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEcECElGamalDecryptor)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalDecryptor")