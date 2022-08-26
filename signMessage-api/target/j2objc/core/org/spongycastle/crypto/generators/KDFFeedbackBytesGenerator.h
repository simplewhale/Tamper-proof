//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/KDFFeedbackBytesGenerator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator")
#ifdef RESTRICT_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator

#if !defined (OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator_) && (INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator || defined(INCLUDE_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator))
#define OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator_

#define RESTRICT_OrgSpongycastleCryptoMacDerivationFunction 1
#define INCLUDE_OrgSpongycastleCryptoMacDerivationFunction 1
#include "org/spongycastle/crypto/MacDerivationFunction.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoDerivationParameters;
@protocol OrgSpongycastleCryptoMac;

@interface OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator : NSObject < OrgSpongycastleCryptoMacDerivationFunction >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)prf;

- (jint)generateBytesWithByteArray:(IOSByteArray *)outArg
                           withInt:(jint)outOff
                           withInt:(jint)len;

- (id<OrgSpongycastleCryptoMac>)getMac;

- (void)init__WithOrgSpongycastleCryptoDerivationParameters:(id<OrgSpongycastleCryptoDerivationParameters>)params OBJC_METHOD_FAMILY_NONE;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator)

FOUNDATION_EXPORT void OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator_initWithOrgSpongycastleCryptoMac_(OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator *self, id<OrgSpongycastleCryptoMac> prf);

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator *new_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator_initWithOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoMac> prf) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator *create_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator_initWithOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoMac> prf);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoGeneratorsKDFFeedbackBytesGenerator")
