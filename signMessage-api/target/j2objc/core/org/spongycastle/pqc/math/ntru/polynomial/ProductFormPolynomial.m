//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/polynomial/ProductFormPolynomial.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/BigIntPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/IntegerPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/ProductFormPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/SparseTernaryPolynomial.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial () {
 @public
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1_;
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2_;
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial, f1_, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial, f2_, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial, f3_, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)

@implementation OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial:(OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)f1
                    withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial:(OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)f2
                    withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial:(OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *)f3 {
  OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(self, f1, f2, f3);
  return self;
}

+ (OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *)generateRandomWithInt:(jint)N
                                                                             withInt:(jint)df1
                                                                             withInt:(jint)df2
                                                                             withInt:(jint)df3Ones
                                                                             withInt:(jint)df3NegOnes
                                                        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_generateRandomWithInt_withInt_withInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df1, df2, df3Ones, df3NegOnes, random);
}

+ (OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *)fromBinaryWithByteArray:(IOSByteArray *)data
                                                                               withInt:(jint)N
                                                                               withInt:(jint)df1
                                                                               withInt:(jint)df2
                                                                               withInt:(jint)df3Ones
                                                                               withInt:(jint)df3NegOnes {
  return OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithByteArray_withInt_withInt_withInt_withInt_withInt_(data, N, df1, df2, df3Ones, df3NegOnes);
}

+ (OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *)fromBinaryWithJavaIoInputStream:(JavaIoInputStream *)is
                                                                                       withInt:(jint)N
                                                                                       withInt:(jint)df1
                                                                                       withInt:(jint)df2
                                                                                       withInt:(jint)df3Ones
                                                                                       withInt:(jint)df3NegOnes {
  return OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(is, N, df1, df2, df3Ones, df3NegOnes);
}

- (IOSByteArray *)toBinary {
  IOSByteArray *f1Bin = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) toBinary];
  IOSByteArray *f2Bin = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) toBinary];
  IOSByteArray *f3Bin = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) toBinary];
  IOSByteArray *all = OrgSpongycastleUtilArrays_copyOfWithByteArray_withInt_(f1Bin, ((IOSByteArray *) nil_chk(f1Bin))->size_ + ((IOSByteArray *) nil_chk(f2Bin))->size_ + ((IOSByteArray *) nil_chk(f3Bin))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(f2Bin, 0, all, f1Bin->size_, f2Bin->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(f3Bin, 0, all, f1Bin->size_ + f2Bin->size_, f3Bin->size_);
  return all;
}

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)b {
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *c = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:b];
  c = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:c];
  [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(c)) addWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:[((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:b]];
  return c;
}

- (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)b {
  OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *c = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:b];
  c = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:c];
  [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(c)) addWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:[((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:b]];
  return c;
}

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)toIntegerPolynomial {
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *i = [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:[((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) toIntegerPolynomial]];
  [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(i)) addWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:[((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) toIntegerPolynomial]];
  return i;
}

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2
                                                                                                                 withInt:(jint)modulus {
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *c = [self multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:poly2];
  [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(c)) modWithInt:modulus];
  return c;
}

- (NSUInteger)hash {
  jint prime = 31;
  jint result = 1;
  result = prime * result + ((f1_ == nil) ? 0 : ((jint) [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f1_)) hash]));
  result = prime * result + ((f2_ == nil) ? 0 : ((jint) [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f2_)) hash]));
  result = prime * result + ((f3_ == nil) ? 0 : ((jint) [((OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *) nil_chk(f3_)) hash]));
  return result;
}

- (jboolean)isEqual:(id)obj {
  if (self == obj) {
    return true;
  }
  if (obj == nil) {
    return false;
  }
  if ([self java_getClass] != [obj java_getClass]) {
    return false;
  }
  OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *other = (OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *) cast_chk(obj, [OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial class]);
  if (f1_ == nil) {
    if (other->f1_ != nil) {
      return false;
    }
  }
  else if (![f1_ isEqual:other->f1_]) {
    return false;
  }
  if (f2_ == nil) {
    if (other->f2_ != nil) {
      return false;
    }
  }
  else if (![f2_ isEqual:other->f2_]) {
    return false;
  }
  if (f3_ == nil) {
    if (other->f3_ != nil) {
      return false;
    }
  }
  else if (![f3_ isEqual:other->f3_]) {
    return false;
  }
  return true;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial;", 0x9, 3, 4, 5, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial;", 0x9, 3, 6, 5, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial;", 0x1, 7, 9, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x1, 7, 10, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 11, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 12, 13, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial:withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial:withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial:);
  methods[1].selector = @selector(generateRandomWithInt:withInt:withInt:withInt:withInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(fromBinaryWithByteArray:withInt:withInt:withInt:withInt:withInt:);
  methods[3].selector = @selector(fromBinaryWithJavaIoInputStream:withInt:withInt:withInt:withInt:withInt:);
  methods[4].selector = @selector(toBinary);
  methods[5].selector = @selector(multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:);
  methods[6].selector = @selector(multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[7].selector = @selector(toIntegerPolynomial);
  methods[8].selector = @selector(multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withInt:);
  methods[9].selector = @selector(hash);
  methods[10].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "f1_", "LOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "f2_", "LOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "f3_", "LOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial;LOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial;LOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial;", "generateRandom", "IIIIILJavaSecuritySecureRandom;", "fromBinary", "[BIIIII", "LJavaIoIOException;", "LJavaIoInputStream;IIIII", "mult", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", "LOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial;", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;I", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial = { "ProductFormPolynomial", "org.spongycastle.pqc.math.ntru.polynomial", ptrTable, methods, fields, 7, 0x1, 11, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial;
}

@end

void OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *self, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3) {
  NSObject_init(self);
  self->f1_ = f1;
  self->f2_ = f2;
  self->f3_ = f3;
}

OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial, initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_, f1, f2, f3)
}

OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2, OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial, initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_, f1, f2, f3)
}

OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_generateRandomWithInt_withInt_withInt_withInt_withInt_withJavaSecuritySecureRandom_(jint N, jint df1, jint df2, jint df3Ones, jint df3NegOnes, JavaSecuritySecureRandom *random) {
  OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initialize();
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1 = OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df1, df1, random);
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2 = OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df2, df2, random);
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3 = OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, df3Ones, df3NegOnes, random);
  return new_OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(f1, f2, f3);
}

OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithByteArray_withInt_withInt_withInt_withInt_withInt_(IOSByteArray *data, jint N, jint df1, jint df2, jint df3Ones, jint df3NegOnes) {
  OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initialize();
  return OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(new_JavaIoByteArrayInputStream_initWithByteArray_(data), N, df1, df2, df3Ones, df3NegOnes);
}

OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(JavaIoInputStream *is, jint N, jint df1, jint df2, jint df3Ones, jint df3NegOnes) {
  OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initialize();
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f1;
  f1 = OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_(is, N, df1, df1);
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f2 = OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_(is, N, df2, df2);
  OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial *f3 = OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_(is, N, df3Ones, df3NegOnes);
  return new_OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_withOrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_(f1, f2, f3);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial)
