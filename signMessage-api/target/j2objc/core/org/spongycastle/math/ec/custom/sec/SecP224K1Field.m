//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP224K1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/custom/sec/SecP224K1Field.h"
#include "org/spongycastle/math/raw/Nat.h"
#include "org/spongycastle/math/raw/Nat224.h"

inline IOSIntArray *OrgSpongycastleMathEcCustomSecSecP224K1Field_get_PExtInv(void);
static IOSIntArray *OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleMathEcCustomSecSecP224K1Field, PExtInv, IOSIntArray *)

inline jint OrgSpongycastleMathEcCustomSecSecP224K1Field_get_P6(void);
#define OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 -1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecP224K1Field, P6, jint)

inline jint OrgSpongycastleMathEcCustomSecSecP224K1Field_get_PExt13(void);
#define OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt13 -1
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecP224K1Field, PExt13, jint)

inline jint OrgSpongycastleMathEcCustomSecSecP224K1Field_get_PInv33(void);
#define OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33 6803
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecP224K1Field, PInv33, jint)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleMathEcCustomSecSecP224K1Field)

IOSIntArray *OrgSpongycastleMathEcCustomSecSecP224K1Field_P;
IOSIntArray *OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt;

@implementation OrgSpongycastleMathEcCustomSecSecP224K1Field

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return OrgSpongycastleMathEcCustomSecSecP224K1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_twiceWithIntArray_withIntArray_(x, z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 11, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 16, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 17, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 18, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 19, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithIntArray:withIntArray:withIntArray:);
  methods[2].selector = @selector(addExtWithIntArray:withIntArray:withIntArray:);
  methods[3].selector = @selector(addOneWithIntArray:withIntArray:);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(halfWithIntArray:withIntArray:);
  methods[6].selector = @selector(multiplyWithIntArray:withIntArray:withIntArray:);
  methods[7].selector = @selector(multiplyAddToExtWithIntArray:withIntArray:withIntArray:);
  methods[8].selector = @selector(negateWithIntArray:withIntArray:);
  methods[9].selector = @selector(reduceWithIntArray:withIntArray:);
  methods[10].selector = @selector(reduce32WithInt:withIntArray:);
  methods[11].selector = @selector(squareWithIntArray:withIntArray:);
  methods[12].selector = @selector(squareNWithIntArray:withInt:withIntArray:);
  methods[13].selector = @selector(subtractWithIntArray:withIntArray:withIntArray:);
  methods[14].selector = @selector(subtractExtWithIntArray:withIntArray:withIntArray:);
  methods[15].selector = @selector(twiceWithIntArray:withIntArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "P", "[I", .constantValue.asLong = 0, 0x18, -1, 20, -1, -1 },
    { "PExt", "[I", .constantValue.asLong = 0, 0x18, -1, 21, -1, -1 },
    { "PExtInv", "[I", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "P6", "I", .constantValue.asInt = OrgSpongycastleMathEcCustomSecSecP224K1Field_P6, 0x1a, -1, -1, -1, -1 },
    { "PExt13", "I", .constantValue.asInt = OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt13, 0x1a, -1, -1, -1, -1 },
    { "PInv33", "I", .constantValue.asInt = OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", &OrgSpongycastleMathEcCustomSecSecP224K1Field_P, &OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt, &OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecP224K1Field = { "SecP224K1Field", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 16, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecP224K1Field;
}

+ (void)initialize {
  if (self == [OrgSpongycastleMathEcCustomSecSecP224K1Field class]) {
    OrgSpongycastleMathEcCustomSecSecP224K1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFE56D, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:7];
    OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x02C23069, (jint) 0x00003526, (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFCADA, (jint) 0xFFFFFFFD, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:14];
    OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFD3DCF97, (jint) 0xFFFFCAD9, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00003525, (jint) 0x00000002 } count:9];
    J2OBJC_SET_INITIALIZED(OrgSpongycastleMathEcCustomSecSecP224K1Field)
  }
}

@end

void OrgSpongycastleMathEcCustomSecSecP224K1Field_init(OrgSpongycastleMathEcCustomSecSecP224K1Field *self) {
  NSObject_init(self);
}

OrgSpongycastleMathEcCustomSecSecP224K1Field *new_OrgSpongycastleMathEcCustomSecSecP224K1Field_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP224K1Field, init)
}

OrgSpongycastleMathEcCustomSecSecP224K1Field *create_OrgSpongycastleMathEcCustomSecSecP224K1Field_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP224K1Field, init)
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat224_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 && OrgSpongycastleMathRawNat224_gteWithIntArray_withIntArray_(z, OrgSpongycastleMathEcCustomSecSecP224K1Field_P))) {
    OrgSpongycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(14, xx, yy, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 13) == OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt13 && OrgSpongycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(14, zz, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt))) {
    if (OrgSpongycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv))->size_, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv, zz) != 0) {
      OrgSpongycastleMathRawNat_incAtWithInt_withIntArray_withInt_(14, zz, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv->size_);
    }
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat_incWithInt_withIntArray_withIntArray_(7, x, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 && OrgSpongycastleMathRawNat224_gteWithIntArray_withIntArray_(z, OrgSpongycastleMathEcCustomSecSecP224K1Field_P))) {
    OrgSpongycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

IOSIntArray *OrgSpongycastleMathEcCustomSecSecP224K1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *z = OrgSpongycastleMathRawNat224_fromBigIntegerWithJavaMathBigInteger_(x);
  if (IOSIntArray_Get(nil_chk(z), 6) == OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 && OrgSpongycastleMathRawNat224_gteWithIntArray_withIntArray_(z, OrgSpongycastleMathEcCustomSecSecP224K1Field_P)) {
    OrgSpongycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
  return z;
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    OrgSpongycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(7, x, 0, z);
  }
  else {
    jint c = OrgSpongycastleMathRawNat224_addWithIntArray_withIntArray_withIntArray_(x, OrgSpongycastleMathEcCustomSecSecP224K1Field_P, z);
    OrgSpongycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(7, z, c);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *tt = OrgSpongycastleMathRawNat224_createExt();
  OrgSpongycastleMathRawNat224_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  OrgSpongycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat224_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 13) == OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt13 && OrgSpongycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(14, zz, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExt))) {
    if (OrgSpongycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv))->size_, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv, zz) != 0) {
      OrgSpongycastleMathRawNat_incAtWithInt_withIntArray_withInt_(14, zz, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv->size_);
    }
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  if (OrgSpongycastleMathRawNat224_isZeroWithIntArray_(x)) {
    OrgSpongycastleMathRawNat224_zeroWithIntArray_(z);
  }
  else {
    OrgSpongycastleMathRawNat224_subWithIntArray_withIntArray_withIntArray_(OrgSpongycastleMathEcCustomSecSecP224K1Field_P, x, z);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jlong cc = OrgSpongycastleMathRawNat224_mul33AddWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, xx, 7, xx, 0, z, 0);
  jint c = OrgSpongycastleMathRawNat224_mul33DWordAddWithInt_withLong_withIntArray_withInt_(OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, cc, z, 0);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 && OrgSpongycastleMathRawNat224_gteWithIntArray_withIntArray_(z, OrgSpongycastleMathEcCustomSecSecP224K1Field_P))) {
    OrgSpongycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  if ((x != 0 && OrgSpongycastleMathRawNat224_mul33WordAddWithInt_withInt_withIntArray_withInt_(OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, x, z, 0) != 0) || (IOSIntArray_Get(nil_chk(z), 6) == OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 && OrgSpongycastleMathRawNat224_gteWithIntArray_withIntArray_(z, OrgSpongycastleMathEcCustomSecSecP224K1Field_P))) {
    OrgSpongycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *tt = OrgSpongycastleMathRawNat224_createExt();
  OrgSpongycastleMathRawNat224_squareWithIntArray_withIntArray_(x, tt);
  OrgSpongycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  IOSIntArray *tt = OrgSpongycastleMathRawNat224_createExt();
  OrgSpongycastleMathRawNat224_squareWithIntArray_withIntArray_(x, tt);
  OrgSpongycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    OrgSpongycastleMathRawNat224_squareWithIntArray_withIntArray_(z, tt);
    OrgSpongycastleMathEcCustomSecSecP224K1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat224_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    OrgSpongycastleMathRawNat_sub33FromWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(14, xx, yy, zz);
  if (c != 0) {
    if (OrgSpongycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv))->size_, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv, zz) != 0) {
      OrgSpongycastleMathRawNat_decAtWithInt_withIntArray_withInt_(14, zz, OrgSpongycastleMathEcCustomSecSecP224K1Field_PExtInv->size_);
    }
  }
}

void OrgSpongycastleMathEcCustomSecSecP224K1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleMathEcCustomSecSecP224K1Field_initialize();
  jint c = OrgSpongycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(7, x, 0, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 6) == OrgSpongycastleMathEcCustomSecSecP224K1Field_P6 && OrgSpongycastleMathRawNat224_gteWithIntArray_withIntArray_(z, OrgSpongycastleMathEcCustomSecSecP224K1Field_P))) {
    OrgSpongycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(7, OrgSpongycastleMathEcCustomSecSecP224K1Field_PInv33, z);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecP224K1Field)
