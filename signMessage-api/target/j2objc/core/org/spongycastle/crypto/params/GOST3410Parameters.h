//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/GOST3410Parameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410Parameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsGOST3410Parameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410Parameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410Parameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsGOST3410Parameters

#if !defined (OrgSpongycastleCryptoParamsGOST3410Parameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410Parameters || defined(INCLUDE_OrgSpongycastleCryptoParamsGOST3410Parameters))
#define OrgSpongycastleCryptoParamsGOST3410Parameters_

#define RESTRICT_OrgSpongycastleCryptoCipherParameters 1
#define INCLUDE_OrgSpongycastleCryptoCipherParameters 1
#include "org/spongycastle/crypto/CipherParameters.h"

@class JavaMathBigInteger;
@class OrgSpongycastleCryptoParamsGOST3410ValidationParameters;

@interface OrgSpongycastleCryptoParamsGOST3410Parameters : NSObject < OrgSpongycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)a;

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)a
withOrgSpongycastleCryptoParamsGOST3410ValidationParameters:(OrgSpongycastleCryptoParamsGOST3410ValidationParameters *)params;

- (jboolean)isEqual:(id)obj;

- (JavaMathBigInteger *)getA;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (OrgSpongycastleCryptoParamsGOST3410ValidationParameters *)getValidationParameters;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsGOST3410Parameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsGOST3410Parameters *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410Parameters *new_OrgSpongycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410Parameters *create_OrgSpongycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsGOST3410ValidationParameters_(OrgSpongycastleCryptoParamsGOST3410Parameters *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a, OrgSpongycastleCryptoParamsGOST3410ValidationParameters *params);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410Parameters *new_OrgSpongycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsGOST3410ValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a, OrgSpongycastleCryptoParamsGOST3410ValidationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsGOST3410Parameters *create_OrgSpongycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsGOST3410ValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a, OrgSpongycastleCryptoParamsGOST3410ValidationParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsGOST3410Parameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsGOST3410Parameters")
