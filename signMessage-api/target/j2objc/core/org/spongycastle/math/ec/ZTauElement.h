//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/ZTauElement.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcZTauElement")
#ifdef RESTRICT_OrgSpongycastleMathEcZTauElement
#define INCLUDE_ALL_OrgSpongycastleMathEcZTauElement 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcZTauElement 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcZTauElement

#if !defined (OrgSpongycastleMathEcZTauElement_) && (INCLUDE_ALL_OrgSpongycastleMathEcZTauElement || defined(INCLUDE_OrgSpongycastleMathEcZTauElement))
#define OrgSpongycastleMathEcZTauElement_

@class JavaMathBigInteger;

@interface OrgSpongycastleMathEcZTauElement : NSObject {
 @public
  JavaMathBigInteger *u_;
  JavaMathBigInteger *v_;
}

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)u
                    withJavaMathBigInteger:(JavaMathBigInteger *)v;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcZTauElement)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcZTauElement, u_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcZTauElement, v_, JavaMathBigInteger *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleMathEcZTauElement *self, JavaMathBigInteger *u, JavaMathBigInteger *v);

FOUNDATION_EXPORT OrgSpongycastleMathEcZTauElement *new_OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *u, JavaMathBigInteger *v) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcZTauElement *create_OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *u, JavaMathBigInteger *v);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcZTauElement)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcZTauElement")
