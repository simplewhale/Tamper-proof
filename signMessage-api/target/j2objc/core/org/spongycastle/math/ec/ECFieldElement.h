//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/ECFieldElement.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement")
#ifdef RESTRICT_OrgSpongycastleMathEcECFieldElement
#define INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcECFieldElement
#ifdef INCLUDE_OrgSpongycastleMathEcECFieldElement_F2m
#define INCLUDE_OrgSpongycastleMathEcECFieldElement 1
#endif
#ifdef INCLUDE_OrgSpongycastleMathEcECFieldElement_Fp
#define INCLUDE_OrgSpongycastleMathEcECFieldElement 1
#endif

#if !defined (OrgSpongycastleMathEcECFieldElement_) && (INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement || defined(INCLUDE_OrgSpongycastleMathEcECFieldElement))
#define OrgSpongycastleMathEcECFieldElement_

#define RESTRICT_OrgSpongycastleMathEcECConstants 1
#define INCLUDE_OrgSpongycastleMathEcECConstants 1
#include "org/spongycastle/math/ec/ECConstants.h"

@class IOSByteArray;
@class JavaMathBigInteger;

@interface OrgSpongycastleMathEcECFieldElement : NSObject < OrgSpongycastleMathEcECConstants >

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)addOne;

- (jint)bitLength;

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (IOSByteArray *)getEncoded;

- (NSString *)getFieldName;

- (jint)getFieldSize;

- (OrgSpongycastleMathEcECFieldElement *)invert;

- (jboolean)isOne;

- (jboolean)isZero;

- (OrgSpongycastleMathEcECFieldElement *)multiplyWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)multiplyMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)multiplyPlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)negate;

- (OrgSpongycastleMathEcECFieldElement *)sqrt;

- (OrgSpongycastleMathEcECFieldElement *)square;

- (OrgSpongycastleMathEcECFieldElement *)squareMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                           withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)squarePlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                          withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)squarePowWithInt:(jint)pow;

- (OrgSpongycastleMathEcECFieldElement *)subtractWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (jboolean)testBitZero;

- (JavaMathBigInteger *)toBigInteger;

- (NSString *)description;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcECFieldElement)

FOUNDATION_EXPORT void OrgSpongycastleMathEcECFieldElement_init(OrgSpongycastleMathEcECFieldElement *self);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcECFieldElement)

#endif

#if !defined (OrgSpongycastleMathEcECFieldElement_Fp_) && (INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement || defined(INCLUDE_OrgSpongycastleMathEcECFieldElement_Fp))
#define OrgSpongycastleMathEcECFieldElement_Fp_

@class JavaMathBigInteger;
@class OrgSpongycastleMathEcECFieldElement;

@interface OrgSpongycastleMathEcECFieldElement_Fp : OrgSpongycastleMathEcECFieldElement {
 @public
  JavaMathBigInteger *q_;
  JavaMathBigInteger *r_;
  JavaMathBigInteger *x_;
}

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)x;

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)addOne;

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)other;

- (NSString *)getFieldName;

- (jint)getFieldSize;

- (JavaMathBigInteger *)getQ;

- (NSUInteger)hash;

- (OrgSpongycastleMathEcECFieldElement *)invert;

- (OrgSpongycastleMathEcECFieldElement *)multiplyWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)multiplyMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)multiplyPlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)negate;

- (OrgSpongycastleMathEcECFieldElement *)sqrt;

- (OrgSpongycastleMathEcECFieldElement *)square;

- (OrgSpongycastleMathEcECFieldElement *)squareMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                           withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)squarePlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                          withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)subtractWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (JavaMathBigInteger *)toBigInteger;

#pragma mark Protected

- (JavaMathBigInteger *)modAddWithJavaMathBigInteger:(JavaMathBigInteger *)x1
                              withJavaMathBigInteger:(JavaMathBigInteger *)x2;

- (JavaMathBigInteger *)modDoubleWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modHalfWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modHalfAbsWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modInverseWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modMultWithJavaMathBigInteger:(JavaMathBigInteger *)x1
                               withJavaMathBigInteger:(JavaMathBigInteger *)x2;

- (JavaMathBigInteger *)modReduceWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modSubtractWithJavaMathBigInteger:(JavaMathBigInteger *)x1
                                   withJavaMathBigInteger:(JavaMathBigInteger *)x2;

#pragma mark Package-Private

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)r
                    withJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (JavaMathBigInteger *)calculateResidueWithJavaMathBigInteger:(JavaMathBigInteger *)p;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcECFieldElement_Fp)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcECFieldElement_Fp, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcECFieldElement_Fp, r_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcECFieldElement_Fp, x_, JavaMathBigInteger *)

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastleMathEcECFieldElement_Fp_calculateResidueWithJavaMathBigInteger_(JavaMathBigInteger *p);

FOUNDATION_EXPORT void OrgSpongycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleMathEcECFieldElement_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *x);

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_Fp *new_OrgSpongycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_Fp *create_OrgSpongycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleMathEcECFieldElement_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *r, JavaMathBigInteger *x);

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_Fp *new_OrgSpongycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *r, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_Fp *create_OrgSpongycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *r, JavaMathBigInteger *x);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcECFieldElement_Fp)

#endif

#if !defined (OrgSpongycastleMathEcECFieldElement_F2m_) && (INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement || defined(INCLUDE_OrgSpongycastleMathEcECFieldElement_F2m))
#define OrgSpongycastleMathEcECFieldElement_F2m_

@class JavaMathBigInteger;
@class OrgSpongycastleMathEcECFieldElement;

@interface OrgSpongycastleMathEcECFieldElement_F2m : OrgSpongycastleMathEcECFieldElement

#pragma mark Public

- (instancetype)initWithInt:(jint)m
                    withInt:(jint)k
     withJavaMathBigInteger:(JavaMathBigInteger *)x;

- (instancetype)initWithInt:(jint)m
                    withInt:(jint)k1
                    withInt:(jint)k2
                    withInt:(jint)k3
     withJavaMathBigInteger:(JavaMathBigInteger *)x;

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)addOne;

- (jint)bitLength;

+ (void)checkFieldElementsWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)a
                          withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)anObject;

- (NSString *)getFieldName;

- (jint)getFieldSize;

- (jint)getK1;

- (jint)getK2;

- (jint)getK3;

- (jint)getM;

- (jint)getRepresentation;

- (NSUInteger)hash;

- (OrgSpongycastleMathEcECFieldElement *)invert;

- (jboolean)isOne;

- (jboolean)isZero;

- (OrgSpongycastleMathEcECFieldElement *)multiplyWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)multiplyMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)multiplyPlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)negate;

- (OrgSpongycastleMathEcECFieldElement *)sqrt;

- (OrgSpongycastleMathEcECFieldElement *)square;

- (OrgSpongycastleMathEcECFieldElement *)squareMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                           withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)squarePlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                          withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (OrgSpongycastleMathEcECFieldElement *)squarePowWithInt:(jint)pow;

- (OrgSpongycastleMathEcECFieldElement *)subtractWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (jboolean)testBitZero;

- (JavaMathBigInteger *)toBigInteger;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcECFieldElement_F2m)

inline jint OrgSpongycastleMathEcECFieldElement_F2m_get_GNB(void);
#define OrgSpongycastleMathEcECFieldElement_F2m_GNB 1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcECFieldElement_F2m, GNB, jint)

inline jint OrgSpongycastleMathEcECFieldElement_F2m_get_TPB(void);
#define OrgSpongycastleMathEcECFieldElement_F2m_TPB 2
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcECFieldElement_F2m, TPB, jint)

inline jint OrgSpongycastleMathEcECFieldElement_F2m_get_PPB(void);
#define OrgSpongycastleMathEcECFieldElement_F2m_PPB 3
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcECFieldElement_F2m, PPB, jint)

FOUNDATION_EXPORT void OrgSpongycastleMathEcECFieldElement_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_(OrgSpongycastleMathEcECFieldElement_F2m *self, jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *x);

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_F2m *new_OrgSpongycastleMathEcECFieldElement_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_F2m *create_OrgSpongycastleMathEcECFieldElement_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcECFieldElement_F2m_initWithInt_withInt_withJavaMathBigInteger_(OrgSpongycastleMathEcECFieldElement_F2m *self, jint m, jint k, JavaMathBigInteger *x);

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_F2m *new_OrgSpongycastleMathEcECFieldElement_F2m_initWithInt_withInt_withJavaMathBigInteger_(jint m, jint k, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcECFieldElement_F2m *create_OrgSpongycastleMathEcECFieldElement_F2m_initWithInt_withInt_withJavaMathBigInteger_(jint m, jint k, JavaMathBigInteger *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcECFieldElement_F2m_checkFieldElementsWithOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECFieldElement *a, OrgSpongycastleMathEcECFieldElement *b);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcECFieldElement_F2m)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcECFieldElement")