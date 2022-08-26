//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/NaccacheSternPrivateKeyParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters

#if !defined (OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters))
#define OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters_

#define RESTRICT_OrgSpongycastleCryptoParamsNaccacheSternKeyParameters 1
#define INCLUDE_OrgSpongycastleCryptoParamsNaccacheSternKeyParameters 1
#include "org/spongycastle/crypto/params/NaccacheSternKeyParameters.h"

@class JavaMathBigInteger;
@class JavaUtilVector;

@interface OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters : OrgSpongycastleCryptoParamsNaccacheSternKeyParameters

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)n
                                   withInt:(jint)lowerSigmaBound
                        withJavaUtilVector:(JavaUtilVector *)smallPrimes
                    withJavaMathBigInteger:(JavaMathBigInteger *)phi_n;

- (JavaMathBigInteger *)getPhi_n;

- (JavaUtilVector *)getSmallPrimes;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithBoolean:(jboolean)arg0
         withJavaMathBigInteger:(JavaMathBigInteger *)arg1
         withJavaMathBigInteger:(JavaMathBigInteger *)arg2
                        withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaUtilVector_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters *self, JavaMathBigInteger *g, JavaMathBigInteger *n, jint lowerSigmaBound, JavaUtilVector *smallPrimes, JavaMathBigInteger *phi_n);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters *new_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaUtilVector_withJavaMathBigInteger_(JavaMathBigInteger *g, JavaMathBigInteger *n, jint lowerSigmaBound, JavaUtilVector *smallPrimes, JavaMathBigInteger *phi_n) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters *create_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaUtilVector_withJavaMathBigInteger_(JavaMathBigInteger *g, JavaMathBigInteger *n, jint lowerSigmaBound, JavaUtilVector *smallPrimes, JavaMathBigInteger *phi_n);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsNaccacheSternPrivateKeyParameters")
