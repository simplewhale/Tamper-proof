//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/ec/ECElGamalEncryptor.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalEncryptor")
#ifdef RESTRICT_OrgSpongycastleCryptoEcECElGamalEncryptor
#define INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalEncryptor 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalEncryptor 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEcECElGamalEncryptor

#if !defined (OrgSpongycastleCryptoEcECElGamalEncryptor_) && (INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalEncryptor || defined(INCLUDE_OrgSpongycastleCryptoEcECElGamalEncryptor))
#define OrgSpongycastleCryptoEcECElGamalEncryptor_

#define RESTRICT_OrgSpongycastleCryptoEcECEncryptor 1
#define INCLUDE_OrgSpongycastleCryptoEcECEncryptor 1
#include "org/spongycastle/crypto/ec/ECEncryptor.h"

@class OrgSpongycastleCryptoEcECPair;
@class OrgSpongycastleMathEcECPoint;
@protocol OrgSpongycastleCryptoCipherParameters;
@protocol OrgSpongycastleMathEcECMultiplier;

@interface OrgSpongycastleCryptoEcECElGamalEncryptor : NSObject < OrgSpongycastleCryptoEcECEncryptor >

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleCryptoEcECPair *)encryptWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)point;

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

#pragma mark Protected

- (id<OrgSpongycastleMathEcECMultiplier>)createBasePointMultiplier;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEcECElGamalEncryptor)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEcECElGamalEncryptor_init(OrgSpongycastleCryptoEcECElGamalEncryptor *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEcECElGamalEncryptor *new_OrgSpongycastleCryptoEcECElGamalEncryptor_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEcECElGamalEncryptor *create_OrgSpongycastleCryptoEcECElGamalEncryptor_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEcECElGamalEncryptor)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEcECElGamalEncryptor")
