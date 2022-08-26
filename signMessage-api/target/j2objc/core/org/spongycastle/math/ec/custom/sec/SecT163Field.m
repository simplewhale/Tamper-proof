//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT163Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/custom/sec/SecT163Field.h"
#include "org/spongycastle/math/raw/Interleave.h"
#include "org/spongycastle/math/raw/Nat192.h"

inline jlong OrgSpongycastleMathEcCustomSecSecT163Field_get_M35(void);
#define OrgSpongycastleMathEcCustomSecSecT163Field_M35 34359738367LL
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecT163Field, M35, jlong)

inline jlong OrgSpongycastleMathEcCustomSecSecT163Field_get_M55(void);
#define OrgSpongycastleMathEcCustomSecSecT163Field_M55 36028797018963967LL
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecT163Field, M55, jlong)

inline IOSLongArray *OrgSpongycastleMathEcCustomSecSecT163Field_get_ROOT_Z(void);
static IOSLongArray *OrgSpongycastleMathEcCustomSecSecT163Field_ROOT_Z;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleMathEcCustomSecSecT163Field, ROOT_Z, IOSLongArray *)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleMathEcCustomSecSecT163Field)

@implementation OrgSpongycastleMathEcCustomSecSecT163Field

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecT163Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_addWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)addExtWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)yy
              withLongArray:(IOSLongArray *)zz {
  OrgSpongycastleMathEcCustomSecSecT163Field_addExtWithLongArray_withLongArray_withLongArray_(xx, yy, zz);
}

+ (void)addOneWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_addOneWithLongArray_withLongArray_(x, z);
}

+ (IOSLongArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return OrgSpongycastleMathEcCustomSecSecT163Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)invertWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_invertWithLongArray_withLongArray_(x, z);
}

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)multiplyAddToExtWithLongArray:(IOSLongArray *)x
                        withLongArray:(IOSLongArray *)y
                        withLongArray:(IOSLongArray *)zz {
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)reduceWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(xx, z);
}

+ (void)reduce29WithLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff {
  OrgSpongycastleMathEcCustomSecSecT163Field_reduce29WithLongArray_withInt_(z, zOff);
}

+ (void)sqrtWithLongArray:(IOSLongArray *)x
            withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_sqrtWithLongArray_withLongArray_(x, z);
}

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_squareWithLongArray_withLongArray_(x, z);
}

+ (void)squareAddToExtWithLongArray:(IOSLongArray *)x
                      withLongArray:(IOSLongArray *)zz {
  OrgSpongycastleMathEcCustomSecSecT163Field_squareAddToExtWithLongArray_withLongArray_(x, zz);
}

+ (void)squareNWithLongArray:(IOSLongArray *)x
                     withInt:(jint)n
               withLongArray:(IOSLongArray *)z {
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(x, n, z);
}

+ (jint)traceWithLongArray:(IOSLongArray *)x {
  return OrgSpongycastleMathEcCustomSecSecT163Field_traceWithLongArray_(x);
}

+ (void)implCompactExtWithLongArray:(IOSLongArray *)zz {
  OrgSpongycastleMathEcCustomSecSecT163Field_implCompactExtWithLongArray_(zz);
}

+ (void)implMultiplyWithLongArray:(IOSLongArray *)x
                    withLongArray:(IOSLongArray *)y
                    withLongArray:(IOSLongArray *)zz {
  OrgSpongycastleMathEcCustomSecSecT163Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)implMulwWithLong:(jlong)x
                withLong:(jlong)y
           withLongArray:(IOSLongArray *)z
                 withInt:(jint)zOff {
  OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(x, y, z, zOff);
}

+ (void)implSquareWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)zz {
  OrgSpongycastleMathEcCustomSecSecT163Field_implSquareWithLongArray_withLongArray_(x, zz);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 13, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 17, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 18, 19, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 20, 19, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 21, 1, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 22, 23, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 24, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithLongArray:withLongArray:withLongArray:);
  methods[2].selector = @selector(addExtWithLongArray:withLongArray:withLongArray:);
  methods[3].selector = @selector(addOneWithLongArray:withLongArray:);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(invertWithLongArray:withLongArray:);
  methods[6].selector = @selector(multiplyWithLongArray:withLongArray:withLongArray:);
  methods[7].selector = @selector(multiplyAddToExtWithLongArray:withLongArray:withLongArray:);
  methods[8].selector = @selector(reduceWithLongArray:withLongArray:);
  methods[9].selector = @selector(reduce29WithLongArray:withInt:);
  methods[10].selector = @selector(sqrtWithLongArray:withLongArray:);
  methods[11].selector = @selector(squareWithLongArray:withLongArray:);
  methods[12].selector = @selector(squareAddToExtWithLongArray:withLongArray:);
  methods[13].selector = @selector(squareNWithLongArray:withInt:withLongArray:);
  methods[14].selector = @selector(traceWithLongArray:);
  methods[15].selector = @selector(implCompactExtWithLongArray:);
  methods[16].selector = @selector(implMultiplyWithLongArray:withLongArray:withLongArray:);
  methods[17].selector = @selector(implMulwWithLong:withLong:withLongArray:withInt:);
  methods[18].selector = @selector(implSquareWithLongArray:withLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M35", "J", .constantValue.asLong = OrgSpongycastleMathEcCustomSecSecT163Field_M35, 0x1a, -1, -1, -1, -1 },
    { "M55", "J", .constantValue.asLong = OrgSpongycastleMathEcCustomSecSecT163Field_M55, 0x1a, -1, -1, -1, -1 },
    { "ROOT_Z", "[J", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[J[J[J", "addExt", "addOne", "[J[J", "fromBigInteger", "LJavaMathBigInteger;", "invert", "multiply", "multiplyAddToExt", "reduce", "reduce29", "[JI", "sqrt", "square", "squareAddToExt", "squareN", "[JI[J", "trace", "[J", "implCompactExt", "implMultiply", "implMulw", "JJ[JI", "implSquare", &OrgSpongycastleMathEcCustomSecSecT163Field_ROOT_Z };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecT163Field = { "SecT163Field", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 19, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecT163Field;
}

+ (void)initialize {
  if (self == [OrgSpongycastleMathEcCustomSecSecT163Field class]) {
    OrgSpongycastleMathEcCustomSecSecT163Field_ROOT_Z = [IOSLongArray newArrayWithLongs:(jlong[]){ (jlong) 0xB6DB6DB6DB6DB6B0LL, (jlong) 0x492492492492DB6DLL, (jlong) 0x492492492LL } count:3];
    J2OBJC_SET_INITIALIZED(OrgSpongycastleMathEcCustomSecSecT163Field)
  }
}

@end

void OrgSpongycastleMathEcCustomSecSecT163Field_init(OrgSpongycastleMathEcCustomSecSecT163Field *self) {
  NSObject_init(self);
}

OrgSpongycastleMathEcCustomSecSecT163Field *new_OrgSpongycastleMathEcCustomSecSecT163Field_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecT163Field, init)
}

OrgSpongycastleMathEcCustomSecSecT163Field *create_OrgSpongycastleMathEcCustomSecSecT163Field_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecT163Field, init)
}

void OrgSpongycastleMathEcCustomSecSecT163Field_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1) ^ IOSLongArray_Get(y, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2) ^ IOSLongArray_Get(y, 2);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_addExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *yy, IOSLongArray *zz) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  *IOSLongArray_GetRef(nil_chk(zz), 0) = IOSLongArray_Get(nil_chk(xx), 0) ^ IOSLongArray_Get(nil_chk(yy), 0);
  *IOSLongArray_GetRef(zz, 1) = IOSLongArray_Get(xx, 1) ^ IOSLongArray_Get(yy, 1);
  *IOSLongArray_GetRef(zz, 2) = IOSLongArray_Get(xx, 2) ^ IOSLongArray_Get(yy, 2);
  *IOSLongArray_GetRef(zz, 3) = IOSLongArray_Get(xx, 3) ^ IOSLongArray_Get(yy, 3);
  *IOSLongArray_GetRef(zz, 4) = IOSLongArray_Get(xx, 4) ^ IOSLongArray_Get(yy, 4);
  *IOSLongArray_GetRef(zz, 5) = IOSLongArray_Get(xx, 5) ^ IOSLongArray_Get(yy, 5);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_addOneWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ 1LL;
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2);
}

IOSLongArray *OrgSpongycastleMathEcCustomSecSecT163Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *z = OrgSpongycastleMathRawNat192_fromBigInteger64WithJavaMathBigInteger_(x);
  OrgSpongycastleMathEcCustomSecSecT163Field_reduce29WithLongArray_withInt_(z, 0);
  return z;
}

void OrgSpongycastleMathEcCustomSecSecT163Field_invertWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  if (OrgSpongycastleMathRawNat192_isZero64WithLongArray_(x)) {
    @throw new_JavaLangIllegalStateException_init();
  }
  IOSLongArray *t0 = OrgSpongycastleMathRawNat192_create64();
  IOSLongArray *t1 = OrgSpongycastleMathRawNat192_create64();
  OrgSpongycastleMathEcCustomSecSecT163Field_squareWithLongArray_withLongArray_(x, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t0, 1, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t1, 1, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t0, 3, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t1, 3, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t0, 9, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t1, 9, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t0, 27, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t1, 27, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(t0, 81, t1);
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, z);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *tt = OrgSpongycastleMathRawNat192_createExt64();
  OrgSpongycastleMathEcCustomSecSecT163Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  OrgSpongycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(tt, z);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *tt = OrgSpongycastleMathRawNat192_createExt64();
  OrgSpongycastleMathEcCustomSecSecT163Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  OrgSpongycastleMathEcCustomSecSecT163Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(xx), 0);
  jlong x1 = IOSLongArray_Get(xx, 1);
  jlong x2 = IOSLongArray_Get(xx, 2);
  jlong x3 = IOSLongArray_Get(xx, 3);
  jlong x4 = IOSLongArray_Get(xx, 4);
  jlong x5 = IOSLongArray_Get(xx, 5);
  x2 ^= (JreLShift64(x5, 29)) ^ (JreLShift64(x5, 32)) ^ (JreLShift64(x5, 35)) ^ (JreLShift64(x5, 36));
  x3 ^= (JreURShift64(x5, 35)) ^ (JreURShift64(x5, 32)) ^ (JreURShift64(x5, 29)) ^ (JreURShift64(x5, 28));
  x1 ^= (JreLShift64(x4, 29)) ^ (JreLShift64(x4, 32)) ^ (JreLShift64(x4, 35)) ^ (JreLShift64(x4, 36));
  x2 ^= (JreURShift64(x4, 35)) ^ (JreURShift64(x4, 32)) ^ (JreURShift64(x4, 29)) ^ (JreURShift64(x4, 28));
  x0 ^= (JreLShift64(x3, 29)) ^ (JreLShift64(x3, 32)) ^ (JreLShift64(x3, 35)) ^ (JreLShift64(x3, 36));
  x1 ^= (JreURShift64(x3, 35)) ^ (JreURShift64(x3, 32)) ^ (JreURShift64(x3, 29)) ^ (JreURShift64(x3, 28));
  jlong t = JreURShift64(x2, 35);
  *IOSLongArray_GetRef(nil_chk(z), 0) = x0 ^ t ^ (JreLShift64(t, 3)) ^ (JreLShift64(t, 6)) ^ (JreLShift64(t, 7));
  *IOSLongArray_GetRef(z, 1) = x1;
  *IOSLongArray_GetRef(z, 2) = x2 & OrgSpongycastleMathEcCustomSecSecT163Field_M35;
}

void OrgSpongycastleMathEcCustomSecSecT163Field_reduce29WithLongArray_withInt_(IOSLongArray *z, jint zOff) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  jlong z2 = IOSLongArray_Get(nil_chk(z), zOff + 2);
  jlong t = JreURShift64(z2, 35);
  *IOSLongArray_GetRef(z, zOff) ^= t ^ (JreLShift64(t, 3)) ^ (JreLShift64(t, 6)) ^ (JreLShift64(t, 7));
  *IOSLongArray_GetRef(z, zOff + 2) = z2 & OrgSpongycastleMathEcCustomSecSecT163Field_M35;
}

void OrgSpongycastleMathEcCustomSecSecT163Field_sqrtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *odd = OrgSpongycastleMathRawNat192_create64();
  jlong u0;
  jlong u1;
  u0 = OrgSpongycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(nil_chk(x), 0));
  u1 = OrgSpongycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 1));
  jlong e0 = (u0 & (jlong) 0x00000000FFFFFFFFLL) | (JreLShift64(u1, 32));
  *IOSLongArray_GetRef(nil_chk(odd), 0) = (JreURShift64(u0, 32)) | (u1 & (jlong) 0xFFFFFFFF00000000LL);
  u0 = OrgSpongycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 2));
  jlong e1 = (u0 & (jlong) 0x00000000FFFFFFFFLL);
  *IOSLongArray_GetRef(odd, 1) = (JreURShift64(u0, 32));
  OrgSpongycastleMathEcCustomSecSecT163Field_multiplyWithLongArray_withLongArray_withLongArray_(odd, OrgSpongycastleMathEcCustomSecSecT163Field_ROOT_Z, z);
  *IOSLongArray_GetRef(nil_chk(z), 0) ^= e0;
  *IOSLongArray_GetRef(z, 1) ^= e1;
}

void OrgSpongycastleMathEcCustomSecSecT163Field_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *tt = OrgSpongycastleMathRawNat192_createExt64();
  OrgSpongycastleMathEcCustomSecSecT163Field_implSquareWithLongArray_withLongArray_(x, tt);
  OrgSpongycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(tt, z);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_squareAddToExtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *tt = OrgSpongycastleMathRawNat192_createExt64();
  OrgSpongycastleMathEcCustomSecSecT163Field_implSquareWithLongArray_withLongArray_(x, tt);
  OrgSpongycastleMathEcCustomSecSecT163Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_squareNWithLongArray_withInt_withLongArray_(IOSLongArray *x, jint n, IOSLongArray *z) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *tt = OrgSpongycastleMathRawNat192_createExt64();
  OrgSpongycastleMathEcCustomSecSecT163Field_implSquareWithLongArray_withLongArray_(x, tt);
  OrgSpongycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(tt, z);
  while (--n > 0) {
    OrgSpongycastleMathEcCustomSecSecT163Field_implSquareWithLongArray_withLongArray_(z, tt);
    OrgSpongycastleMathEcCustomSecSecT163Field_reduceWithLongArray_withLongArray_(tt, z);
  }
}

jint OrgSpongycastleMathEcCustomSecSecT163Field_traceWithLongArray_(IOSLongArray *x) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  return (jint) (IOSLongArray_Get(nil_chk(x), 0) ^ (JreURShift64(IOSLongArray_Get(x, 2), 29))) & 1;
}

void OrgSpongycastleMathEcCustomSecSecT163Field_implCompactExtWithLongArray_(IOSLongArray *zz) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  jlong z0 = IOSLongArray_Get(nil_chk(zz), 0);
  jlong z1 = IOSLongArray_Get(zz, 1);
  jlong z2 = IOSLongArray_Get(zz, 2);
  jlong z3 = IOSLongArray_Get(zz, 3);
  jlong z4 = IOSLongArray_Get(zz, 4);
  jlong z5 = IOSLongArray_Get(zz, 5);
  *IOSLongArray_GetRef(zz, 0) = z0 ^ (JreLShift64(z1, 55));
  *IOSLongArray_GetRef(zz, 1) = (JreURShift64(z1, 9)) ^ (JreLShift64(z2, 46));
  *IOSLongArray_GetRef(zz, 2) = (JreURShift64(z2, 18)) ^ (JreLShift64(z3, 37));
  *IOSLongArray_GetRef(zz, 3) = (JreURShift64(z3, 27)) ^ (JreLShift64(z4, 28));
  *IOSLongArray_GetRef(zz, 4) = (JreURShift64(z4, 36)) ^ (JreLShift64(z5, 19));
  *IOSLongArray_GetRef(zz, 5) = (JreURShift64(z5, 45));
}

void OrgSpongycastleMathEcCustomSecSecT163Field_implMultiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  jlong f0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong f1 = IOSLongArray_Get(x, 1);
  jlong f2 = IOSLongArray_Get(x, 2);
  f2 = ((JreURShift64(f1, 46)) ^ (JreLShift64(f2, 18)));
  f1 = ((JreURShift64(f0, 55)) ^ (JreLShift64(f1, 9))) & OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  f0 &= OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  jlong g0 = IOSLongArray_Get(nil_chk(y), 0);
  jlong g1 = IOSLongArray_Get(y, 1);
  jlong g2 = IOSLongArray_Get(y, 2);
  g2 = ((JreURShift64(g1, 46)) ^ (JreLShift64(g2, 18)));
  g1 = ((JreURShift64(g0, 55)) ^ (JreLShift64(g1, 9))) & OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  g0 &= OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  IOSLongArray *H = [IOSLongArray newArrayWithLength:10];
  OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(f0, g0, H, 0);
  OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(f2, g2, H, 2);
  jlong t0 = f0 ^ f1 ^ f2;
  jlong t1 = g0 ^ g1 ^ g2;
  OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(t0, t1, H, 4);
  jlong t2 = (JreLShift64(f1, 1)) ^ (JreLShift64(f2, 2));
  jlong t3 = (JreLShift64(g1, 1)) ^ (JreLShift64(g2, 2));
  OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(f0 ^ t2, g0 ^ t3, H, 6);
  OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(t0 ^ t2, t1 ^ t3, H, 8);
  jlong t4 = IOSLongArray_Get(H, 6) ^ IOSLongArray_Get(H, 8);
  jlong t5 = IOSLongArray_Get(H, 7) ^ IOSLongArray_Get(H, 9);
  jlong v0 = (JreLShift64(t4, 1)) ^ IOSLongArray_Get(H, 6);
  jlong v1 = t4 ^ (JreLShift64(t5, 1)) ^ IOSLongArray_Get(H, 7);
  jlong v2 = t5;
  jlong u0 = IOSLongArray_Get(H, 0);
  jlong u1 = IOSLongArray_Get(H, 1) ^ IOSLongArray_Get(H, 0) ^ IOSLongArray_Get(H, 4);
  jlong u2 = IOSLongArray_Get(H, 1) ^ IOSLongArray_Get(H, 5);
  jlong w0 = u0 ^ v0 ^ (JreLShift64(IOSLongArray_Get(H, 2), 4)) ^ (JreLShift64(IOSLongArray_Get(H, 2), 1));
  jlong w1 = u1 ^ v1 ^ (JreLShift64(IOSLongArray_Get(H, 3), 4)) ^ (JreLShift64(IOSLongArray_Get(H, 3), 1));
  jlong w2 = u2 ^ v2;
  w1 ^= (JreURShift64(w0, 55));
  w0 &= OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  w2 ^= (JreURShift64(w1, 55));
  w1 &= OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  w0 = (JreURShift64(w0, 1)) ^ (JreLShift64((w1 & 1LL), 54));
  w1 = (JreURShift64(w1, 1)) ^ (JreLShift64((w2 & 1LL), 54));
  w2 = (JreURShift64(w2, 1));
  w0 ^= (JreLShift64(w0, 1));
  w0 ^= (JreLShift64(w0, 2));
  w0 ^= (JreLShift64(w0, 4));
  w0 ^= (JreLShift64(w0, 8));
  w0 ^= (JreLShift64(w0, 16));
  w0 ^= (JreLShift64(w0, 32));
  w0 &= OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  w1 ^= (JreURShift64(w0, 54));
  w1 ^= (JreLShift64(w1, 1));
  w1 ^= (JreLShift64(w1, 2));
  w1 ^= (JreLShift64(w1, 4));
  w1 ^= (JreLShift64(w1, 8));
  w1 ^= (JreLShift64(w1, 16));
  w1 ^= (JreLShift64(w1, 32));
  w1 &= OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  w2 ^= (JreURShift64(w1, 54));
  w2 ^= (JreLShift64(w2, 1));
  w2 ^= (JreLShift64(w2, 2));
  w2 ^= (JreLShift64(w2, 4));
  w2 ^= (JreLShift64(w2, 8));
  w2 ^= (JreLShift64(w2, 16));
  w2 ^= (JreLShift64(w2, 32));
  *IOSLongArray_GetRef(nil_chk(zz), 0) = u0;
  *IOSLongArray_GetRef(zz, 1) = u1 ^ w0 ^ IOSLongArray_Get(H, 2);
  *IOSLongArray_GetRef(zz, 2) = u2 ^ w1 ^ w0 ^ IOSLongArray_Get(H, 3);
  *IOSLongArray_GetRef(zz, 3) = w2 ^ w1;
  *IOSLongArray_GetRef(zz, 4) = w2 ^ IOSLongArray_Get(H, 2);
  *IOSLongArray_GetRef(zz, 5) = IOSLongArray_Get(H, 3);
  OrgSpongycastleMathEcCustomSecSecT163Field_implCompactExtWithLongArray_(zz);
}

void OrgSpongycastleMathEcCustomSecSecT163Field_implMulwWithLong_withLong_withLongArray_withInt_(jlong x, jlong y, IOSLongArray *z, jint zOff) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  IOSLongArray *u = [IOSLongArray newArrayWithLength:8];
  *IOSLongArray_GetRef(u, 1) = y;
  *IOSLongArray_GetRef(u, 2) = JreLShift64(IOSLongArray_Get(u, 1), 1);
  *IOSLongArray_GetRef(u, 3) = IOSLongArray_Get(u, 2) ^ y;
  *IOSLongArray_GetRef(u, 4) = JreLShift64(IOSLongArray_Get(u, 2), 1);
  *IOSLongArray_GetRef(u, 5) = IOSLongArray_Get(u, 4) ^ y;
  *IOSLongArray_GetRef(u, 6) = JreLShift64(IOSLongArray_Get(u, 3), 1);
  *IOSLongArray_GetRef(u, 7) = IOSLongArray_Get(u, 6) ^ y;
  jint j = (jint) x;
  jlong g;
  jlong h = 0;
  jlong l = IOSLongArray_Get(u, j & 3);
  jint k = 47;
  do {
    j = (jint) (JreURShift64(x, k));
    g = IOSLongArray_Get(u, j & 7) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 3)) & 7), 3) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 6)) & 7), 6);
    l ^= (JreLShift64(g, k));
    h ^= (JreURShift64(g, -k));
  }
  while ((k -= 9) > 0);
  *IOSLongArray_GetRef(nil_chk(z), zOff) = l & OrgSpongycastleMathEcCustomSecSecT163Field_M55;
  *IOSLongArray_GetRef(z, zOff + 1) = (JreURShift64(l, 55)) ^ (JreLShift64(h, 9));
}

void OrgSpongycastleMathEcCustomSecSecT163Field_implSquareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  OrgSpongycastleMathEcCustomSecSecT163Field_initialize();
  OrgSpongycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(nil_chk(x), 0), zz, 0);
  OrgSpongycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(x, 1), zz, 2);
  jlong x2 = IOSLongArray_Get(x, 2);
  *IOSLongArray_GetRef(nil_chk(zz), 4) = OrgSpongycastleMathRawInterleave_expand32to64WithInt_((jint) x2);
  *IOSLongArray_GetRef(zz, 5) = OrgSpongycastleMathRawInterleave_expand8to16WithInt_((jint) (JreURShift64(x2, 32))) & (jlong) 0xFFFFFFFFLL;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecT163Field)
