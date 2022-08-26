//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT193FieldElement.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193FieldElement")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecT193FieldElement
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193FieldElement 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193FieldElement 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecT193FieldElement

#if !defined (OrgSpongycastleMathEcCustomSecSecT193FieldElement_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193FieldElement || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecT193FieldElement))
#define OrgSpongycastleMathEcCustomSecSecT193FieldElement_

#define RESTRICT_OrgSpongycastleMathEcECFieldElement 1
#define INCLUDE_OrgSpongycastleMathEcECFieldElement 1
#include "org/spongycastle/math/ec/ECFieldElement.h"

@class IOSLongArray;
@class JavaMathBigInteger;

@interface OrgSpongycastleMathEcCustomSecSecT193FieldElement : OrgSpongycastleMathEcECFieldElement {
 @public
  IOSLongArray *x_;
}

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (OrgSpongycastleMathEcECFieldElement *)addOne;

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)other;

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

#pragma mark Protected

- (instancetype)initWithLongArray:(IOSLongArray *)x;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecT193FieldElement)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcCustomSecSecT193FieldElement, x_, IOSLongArray *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT193FieldElement_initWithJavaMathBigInteger_(OrgSpongycastleMathEcCustomSecSecT193FieldElement *self, JavaMathBigInteger *x);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193FieldElement *new_OrgSpongycastleMathEcCustomSecSecT193FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193FieldElement *create_OrgSpongycastleMathEcCustomSecSecT193FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT193FieldElement_init(OrgSpongycastleMathEcCustomSecSecT193FieldElement *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193FieldElement *new_OrgSpongycastleMathEcCustomSecSecT193FieldElement_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193FieldElement *create_OrgSpongycastleMathEcCustomSecSecT193FieldElement_init(void);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT193FieldElement_initWithLongArray_(OrgSpongycastleMathEcCustomSecSecT193FieldElement *self, IOSLongArray *x);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193FieldElement *new_OrgSpongycastleMathEcCustomSecSecT193FieldElement_initWithLongArray_(IOSLongArray *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193FieldElement *create_OrgSpongycastleMathEcCustomSecSecT193FieldElement_initWithLongArray_(IOSLongArray *x);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecT193FieldElement)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193FieldElement")
