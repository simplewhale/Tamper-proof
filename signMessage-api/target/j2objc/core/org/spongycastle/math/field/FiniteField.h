//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/field/FiniteField.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathFieldFiniteField")
#ifdef RESTRICT_OrgSpongycastleMathFieldFiniteField
#define INCLUDE_ALL_OrgSpongycastleMathFieldFiniteField 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathFieldFiniteField 1
#endif
#undef RESTRICT_OrgSpongycastleMathFieldFiniteField

#if !defined (OrgSpongycastleMathFieldFiniteField_) && (INCLUDE_ALL_OrgSpongycastleMathFieldFiniteField || defined(INCLUDE_OrgSpongycastleMathFieldFiniteField))
#define OrgSpongycastleMathFieldFiniteField_

@class JavaMathBigInteger;

@protocol OrgSpongycastleMathFieldFiniteField < JavaObject >

- (JavaMathBigInteger *)getCharacteristic;

- (jint)getDimension;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathFieldFiniteField)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathFieldFiniteField)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathFieldFiniteField")
