//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/gcm/GCMUtil.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/modes/gcm/GCMUtil.h"
#include "org/spongycastle/util/Pack.h"

@interface OrgSpongycastleCryptoModesGcmGCMUtil ()

+ (IOSIntArray *)generateLookup;

@end

inline jint OrgSpongycastleCryptoModesGcmGCMUtil_get_E1(void);
#define OrgSpongycastleCryptoModesGcmGCMUtil_E1 -520093696
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoModesGcmGCMUtil, E1, jint)

inline jlong OrgSpongycastleCryptoModesGcmGCMUtil_get_E1L(void);
#define OrgSpongycastleCryptoModesGcmGCMUtil_E1L -2233785415175766016LL
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoModesGcmGCMUtil, E1L, jlong)

inline IOSIntArray *OrgSpongycastleCryptoModesGcmGCMUtil_get_LOOKUP(void);
static IOSIntArray *OrgSpongycastleCryptoModesGcmGCMUtil_LOOKUP;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoModesGcmGCMUtil, LOOKUP, IOSIntArray *)

__attribute__((unused)) static IOSIntArray *OrgSpongycastleCryptoModesGcmGCMUtil_generateLookup(void);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoModesGcmGCMUtil)

@implementation OrgSpongycastleCryptoModesGcmGCMUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoModesGcmGCMUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSIntArray *)generateLookup {
  return OrgSpongycastleCryptoModesGcmGCMUtil_generateLookup();
}

+ (IOSByteArray *)oneAsBytes {
  return OrgSpongycastleCryptoModesGcmGCMUtil_oneAsBytes();
}

+ (IOSIntArray *)oneAsInts {
  return OrgSpongycastleCryptoModesGcmGCMUtil_oneAsInts();
}

+ (IOSLongArray *)oneAsLongs {
  return OrgSpongycastleCryptoModesGcmGCMUtil_oneAsLongs();
}

+ (IOSByteArray *)asBytesWithIntArray:(IOSIntArray *)x {
  return OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_(x);
}

+ (void)asBytesWithIntArray:(IOSIntArray *)x
              withByteArray:(IOSByteArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_withByteArray_(x, z);
}

+ (IOSByteArray *)asBytesWithLongArray:(IOSLongArray *)x {
  return OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_(x);
}

+ (void)asBytesWithLongArray:(IOSLongArray *)x
               withByteArray:(IOSByteArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_withByteArray_(x, z);
}

+ (IOSIntArray *)asIntsWithByteArray:(IOSByteArray *)x {
  return OrgSpongycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_(x);
}

+ (void)asIntsWithByteArray:(IOSByteArray *)x
               withIntArray:(IOSIntArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_withIntArray_(x, z);
}

+ (IOSLongArray *)asLongsWithByteArray:(IOSByteArray *)x {
  return OrgSpongycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_(x);
}

+ (void)asLongsWithByteArray:(IOSByteArray *)x
               withLongArray:(IOSLongArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_withLongArray_(x, z);
}

+ (void)multiplyWithByteArray:(IOSByteArray *)x
                withByteArray:(IOSByteArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithByteArray_withByteArray_(x, y);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithIntArray_withIntArray_(x, y);
}

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithLongArray_withLongArray_(x, y);
}

+ (void)multiplyPWithIntArray:(IOSIntArray *)x {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_(x);
}

+ (void)multiplyPWithIntArray:(IOSIntArray *)x
                 withIntArray:(IOSIntArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyP8WithIntArray:(IOSIntArray *)x {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_(x);
}

+ (void)multiplyP8WithIntArray:(IOSIntArray *)x
                  withIntArray:(IOSIntArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_withIntArray_(x, y);
}

+ (jint)shiftRightWithIntArray:(IOSIntArray *)x {
  return OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithIntArray_(x);
}

+ (jint)shiftRightWithIntArray:(IOSIntArray *)x
                  withIntArray:(IOSIntArray *)z {
  return OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithIntArray_withIntArray_(x, z);
}

+ (jlong)shiftRightWithLongArray:(IOSLongArray *)x {
  return OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithLongArray_(x);
}

+ (jlong)shiftRightWithLongArray:(IOSLongArray *)x
                   withLongArray:(IOSLongArray *)z {
  return OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithLongArray_withLongArray_(x, z);
}

+ (jint)shiftRightNWithIntArray:(IOSIntArray *)x
                        withInt:(jint)n {
  return OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightNWithIntArray_withInt_(x, n);
}

+ (jint)shiftRightNWithIntArray:(IOSIntArray *)x
                        withInt:(jint)n
                   withIntArray:(IOSIntArray *)z {
  return OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_(x, y);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y
                   withInt:(jint)yOff
                   withInt:(jint)yLen {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withInt_withInt_(x, y, yOff, yLen);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y
             withByteArray:(IOSByteArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withByteArray_(x, y, z);
}

+ (void)xor__WithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_(x, y);
}

+ (void)xor__WithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)y
             withIntArray:(IOSIntArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)xor__WithLongArray:(IOSLongArray *)x
             withLongArray:(IOSLongArray *)y {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_(x, y);
}

+ (void)xor__WithLongArray:(IOSLongArray *)x
             withLongArray:(IOSLongArray *)y
             withLongArray:(IOSLongArray *)z {
  OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0xa, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 4, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 5, 7, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, 8, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 12, -1, -1, -1, -1 },
    { NULL, "I", 0x8, 16, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x8, 16, 12, -1, -1, -1, -1 },
    { NULL, "J", 0x8, 16, 3, -1, -1, -1, -1 },
    { NULL, "J", 0x8, 16, 13, -1, -1, -1, -1 },
    { NULL, "I", 0x8, 17, 18, -1, -1, -1, -1 },
    { NULL, "I", 0x8, 17, 19, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 21, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 22, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 23, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 24, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateLookup);
  methods[2].selector = @selector(oneAsBytes);
  methods[3].selector = @selector(oneAsInts);
  methods[4].selector = @selector(oneAsLongs);
  methods[5].selector = @selector(asBytesWithIntArray:);
  methods[6].selector = @selector(asBytesWithIntArray:withByteArray:);
  methods[7].selector = @selector(asBytesWithLongArray:);
  methods[8].selector = @selector(asBytesWithLongArray:withByteArray:);
  methods[9].selector = @selector(asIntsWithByteArray:);
  methods[10].selector = @selector(asIntsWithByteArray:withIntArray:);
  methods[11].selector = @selector(asLongsWithByteArray:);
  methods[12].selector = @selector(asLongsWithByteArray:withLongArray:);
  methods[13].selector = @selector(multiplyWithByteArray:withByteArray:);
  methods[14].selector = @selector(multiplyWithIntArray:withIntArray:);
  methods[15].selector = @selector(multiplyWithLongArray:withLongArray:);
  methods[16].selector = @selector(multiplyPWithIntArray:);
  methods[17].selector = @selector(multiplyPWithIntArray:withIntArray:);
  methods[18].selector = @selector(multiplyP8WithIntArray:);
  methods[19].selector = @selector(multiplyP8WithIntArray:withIntArray:);
  methods[20].selector = @selector(shiftRightWithIntArray:);
  methods[21].selector = @selector(shiftRightWithIntArray:withIntArray:);
  methods[22].selector = @selector(shiftRightWithLongArray:);
  methods[23].selector = @selector(shiftRightWithLongArray:withLongArray:);
  methods[24].selector = @selector(shiftRightNWithIntArray:withInt:);
  methods[25].selector = @selector(shiftRightNWithIntArray:withInt:withIntArray:);
  methods[26].selector = @selector(xor__WithByteArray:withByteArray:);
  methods[27].selector = @selector(xor__WithByteArray:withByteArray:withInt:withInt:);
  methods[28].selector = @selector(xor__WithByteArray:withByteArray:withByteArray:);
  methods[29].selector = @selector(xor__WithIntArray:withIntArray:);
  methods[30].selector = @selector(xor__WithIntArray:withIntArray:withIntArray:);
  methods[31].selector = @selector(xor__WithLongArray:withLongArray:);
  methods[32].selector = @selector(xor__WithLongArray:withLongArray:withLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "E1", "I", .constantValue.asInt = OrgSpongycastleCryptoModesGcmGCMUtil_E1, 0x1a, -1, -1, -1, -1 },
    { "E1L", "J", .constantValue.asLong = OrgSpongycastleCryptoModesGcmGCMUtil_E1L, 0x1a, -1, -1, -1, -1 },
    { "LOOKUP", "[I", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
  };
  static const void *ptrTable[] = { "asBytes", "[I", "[I[B", "[J", "[J[B", "asInts", "[B", "[B[I", "asLongs", "[B[J", "multiply", "[B[B", "[I[I", "[J[J", "multiplyP", "multiplyP8", "shiftRight", "shiftRightN", "[II", "[II[I", "xor", "[B[BII", "[B[B[B", "[I[I[I", "[J[J[J", &OrgSpongycastleCryptoModesGcmGCMUtil_LOOKUP };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoModesGcmGCMUtil = { "GCMUtil", "org.spongycastle.crypto.modes.gcm", ptrTable, methods, fields, 7, 0x401, 33, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoModesGcmGCMUtil;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoModesGcmGCMUtil class]) {
    OrgSpongycastleCryptoModesGcmGCMUtil_LOOKUP = OrgSpongycastleCryptoModesGcmGCMUtil_generateLookup();
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoModesGcmGCMUtil)
  }
}

@end

void OrgSpongycastleCryptoModesGcmGCMUtil_init(OrgSpongycastleCryptoModesGcmGCMUtil *self) {
  NSObject_init(self);
}

IOSIntArray *OrgSpongycastleCryptoModesGcmGCMUtil_generateLookup() {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSIntArray *lookup = [IOSIntArray newArrayWithLength:256];
  for (jint c = 0; c < 256; ++c) {
    jint v = 0;
    for (jint i = 7; i >= 0; --i) {
      if ((c & (JreLShift32(1, i))) != 0) {
        v ^= (JreURShift32(OrgSpongycastleCryptoModesGcmGCMUtil_E1, (7 - i)));
      }
    }
    *IOSIntArray_GetRef(lookup, c) = v;
  }
  return lookup;
}

IOSByteArray *OrgSpongycastleCryptoModesGcmGCMUtil_oneAsBytes() {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:16];
  *IOSByteArray_GetRef(tmp, 0) = (jbyte) (jint) 0x80;
  return tmp;
}

IOSIntArray *OrgSpongycastleCryptoModesGcmGCMUtil_oneAsInts() {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSIntArray *tmp = [IOSIntArray newArrayWithLength:4];
  *IOSIntArray_GetRef(tmp, 0) = JreLShift32(1, 31);
  return tmp;
}

IOSLongArray *OrgSpongycastleCryptoModesGcmGCMUtil_oneAsLongs() {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *tmp = [IOSLongArray newArrayWithLength:2];
  *IOSLongArray_GetRef(tmp, 0) = JreLShift64(1LL, 63);
  return tmp;
}

IOSByteArray *OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_(IOSIntArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSByteArray *z = [IOSByteArray newArrayWithLength:16];
  OrgSpongycastleUtilPack_intToBigEndianWithIntArray_withByteArray_withInt_(x, z, 0);
  return z;
}

void OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_withByteArray_(IOSIntArray *x, IOSByteArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  OrgSpongycastleUtilPack_intToBigEndianWithIntArray_withByteArray_withInt_(x, z, 0);
}

IOSByteArray *OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_(IOSLongArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSByteArray *z = [IOSByteArray newArrayWithLength:16];
  OrgSpongycastleUtilPack_longToBigEndianWithLongArray_withByteArray_withInt_(x, z, 0);
  return z;
}

void OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_withByteArray_(IOSLongArray *x, IOSByteArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  OrgSpongycastleUtilPack_longToBigEndianWithLongArray_withByteArray_withInt_(x, z, 0);
}

IOSIntArray *OrgSpongycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_(IOSByteArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSIntArray *z = [IOSIntArray newArrayWithLength:4];
  OrgSpongycastleUtilPack_bigEndianToIntWithByteArray_withInt_withIntArray_(x, 0, z);
  return z;
}

void OrgSpongycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_withIntArray_(IOSByteArray *x, IOSIntArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  OrgSpongycastleUtilPack_bigEndianToIntWithByteArray_withInt_withIntArray_(x, 0, z);
}

IOSLongArray *OrgSpongycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_(IOSByteArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *z = [IOSLongArray newArrayWithLength:2];
  OrgSpongycastleUtilPack_bigEndianToLongWithByteArray_withInt_withLongArray_(x, 0, z);
  return z;
}

void OrgSpongycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_withLongArray_(IOSByteArray *x, IOSLongArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  OrgSpongycastleUtilPack_bigEndianToLongWithByteArray_withInt_withLongArray_(x, 0, z);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithByteArray_withByteArray_(IOSByteArray *x, IOSByteArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  IOSIntArray *t1 = OrgSpongycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_(x);
  IOSIntArray *t2 = OrgSpongycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_(y);
  OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithIntArray_withIntArray_(t1, t2);
  OrgSpongycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_withByteArray_(t1, x);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint r00 = IOSIntArray_Get(nil_chk(x), 0);
  jint r01 = IOSIntArray_Get(x, 1);
  jint r02 = IOSIntArray_Get(x, 2);
  jint r03 = IOSIntArray_Get(x, 3);
  jint r10 = 0;
  jint r11 = 0;
  jint r12 = 0;
  jint r13 = 0;
  for (jint i = 0; i < 4; ++i) {
    jint bits = IOSIntArray_Get(nil_chk(y), i);
    for (jint j = 0; j < 32; ++j) {
      jint m1 = JreRShift32(bits, 31);
      JreLShiftAssignInt(&bits, 1);
      r10 ^= (r00 & m1);
      r11 ^= (r01 & m1);
      r12 ^= (r02 & m1);
      r13 ^= (r03 & m1);
      jint m2 = JreRShift32((JreLShift32(r03, 31)), 8);
      r03 = (JreURShift32(r03, 1)) | (JreLShift32(r02, 31));
      r02 = (JreURShift32(r02, 1)) | (JreLShift32(r01, 31));
      r01 = (JreURShift32(r01, 1)) | (JreLShift32(r00, 31));
      r00 = (JreURShift32(r00, 1)) ^ (m2 & OrgSpongycastleCryptoModesGcmGCMUtil_E1);
    }
  }
  *IOSIntArray_GetRef(x, 0) = r10;
  *IOSIntArray_GetRef(x, 1) = r11;
  *IOSIntArray_GetRef(x, 2) = r12;
  *IOSIntArray_GetRef(x, 3) = r13;
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jlong r00 = IOSLongArray_Get(nil_chk(x), 0);
  jlong r01 = IOSLongArray_Get(x, 1);
  jlong r10 = 0;
  jlong r11 = 0;
  for (jint i = 0; i < 2; ++i) {
    jlong bits = IOSLongArray_Get(nil_chk(y), i);
    for (jint j = 0; j < 64; ++j) {
      jlong m1 = JreRShift64(bits, 63);
      JreLShiftAssignLong(&bits, 1);
      r10 ^= (r00 & m1);
      r11 ^= (r01 & m1);
      jlong m2 = JreRShift64((JreLShift64(r01, 63)), 8);
      r01 = (JreURShift64(r01, 1)) | (JreLShift64(r00, 63));
      r00 = (JreURShift64(r00, 1)) ^ (m2 & OrgSpongycastleCryptoModesGcmGCMUtil_E1L);
    }
  }
  *IOSLongArray_GetRef(x, 0) = r10;
  *IOSLongArray_GetRef(x, 1) = r11;
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_(IOSIntArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint m = JreRShift32(OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithIntArray_(x), 8);
  *IOSIntArray_GetRef(nil_chk(x), 0) ^= (m & OrgSpongycastleCryptoModesGcmGCMUtil_E1);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint m = JreRShift32(OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithIntArray_withIntArray_(x, z), 8);
  *IOSIntArray_GetRef(nil_chk(z), 0) ^= (m & OrgSpongycastleCryptoModesGcmGCMUtil_E1);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_(IOSIntArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint c = OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightNWithIntArray_withInt_(x, 8);
  *IOSIntArray_GetRef(nil_chk(x), 0) ^= IOSIntArray_Get(nil_chk(OrgSpongycastleCryptoModesGcmGCMUtil_LOOKUP), JreURShift32(c, 24));
}

void OrgSpongycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint c = OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightNWithIntArray_withInt_withIntArray_(x, 8, y);
  *IOSIntArray_GetRef(nil_chk(y), 0) ^= IOSIntArray_Get(nil_chk(OrgSpongycastleCryptoModesGcmGCMUtil_LOOKUP), JreURShift32(c, 24));
}

jint OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithIntArray_(IOSIntArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint b = IOSIntArray_Get(nil_chk(x), 0);
  *IOSIntArray_GetRef(x, 0) = JreURShift32(b, 1);
  jint c = JreLShift32(b, 31);
  b = IOSIntArray_Get(x, 1);
  *IOSIntArray_GetRef(x, 1) = (JreURShift32(b, 1)) | c;
  c = JreLShift32(b, 31);
  b = IOSIntArray_Get(x, 2);
  *IOSIntArray_GetRef(x, 2) = (JreURShift32(b, 1)) | c;
  c = JreLShift32(b, 31);
  b = IOSIntArray_Get(x, 3);
  *IOSIntArray_GetRef(x, 3) = (JreURShift32(b, 1)) | c;
  return JreLShift32(b, 31);
}

jint OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint b = IOSIntArray_Get(nil_chk(x), 0);
  *IOSIntArray_GetRef(nil_chk(z), 0) = JreURShift32(b, 1);
  jint c = JreLShift32(b, 31);
  b = IOSIntArray_Get(x, 1);
  *IOSIntArray_GetRef(z, 1) = (JreURShift32(b, 1)) | c;
  c = JreLShift32(b, 31);
  b = IOSIntArray_Get(x, 2);
  *IOSIntArray_GetRef(z, 2) = (JreURShift32(b, 1)) | c;
  c = JreLShift32(b, 31);
  b = IOSIntArray_Get(x, 3);
  *IOSIntArray_GetRef(z, 3) = (JreURShift32(b, 1)) | c;
  return JreLShift32(b, 31);
}

jlong OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithLongArray_(IOSLongArray *x) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jlong b = IOSLongArray_Get(nil_chk(x), 0);
  *IOSLongArray_GetRef(x, 0) = JreURShift64(b, 1);
  jlong c = JreLShift64(b, 63);
  b = IOSLongArray_Get(x, 1);
  *IOSLongArray_GetRef(x, 1) = (JreURShift64(b, 1)) | c;
  return JreLShift64(b, 63);
}

jlong OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jlong b = IOSLongArray_Get(nil_chk(x), 0);
  *IOSLongArray_GetRef(nil_chk(z), 0) = JreURShift64(b, 1);
  jlong c = JreLShift64(b, 63);
  b = IOSLongArray_Get(x, 1);
  *IOSLongArray_GetRef(z, 1) = (JreURShift64(b, 1)) | c;
  return JreLShift64(b, 63);
}

jint OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightNWithIntArray_withInt_(IOSIntArray *x, jint n) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint b = IOSIntArray_Get(nil_chk(x), 0);
  jint nInv = 32 - n;
  *IOSIntArray_GetRef(x, 0) = JreURShift32(b, n);
  jint c = JreLShift32(b, nInv);
  b = IOSIntArray_Get(x, 1);
  *IOSIntArray_GetRef(x, 1) = (JreURShift32(b, n)) | c;
  c = JreLShift32(b, nInv);
  b = IOSIntArray_Get(x, 2);
  *IOSIntArray_GetRef(x, 2) = (JreURShift32(b, n)) | c;
  c = JreLShift32(b, nInv);
  b = IOSIntArray_Get(x, 3);
  *IOSIntArray_GetRef(x, 3) = (JreURShift32(b, n)) | c;
  return JreLShift32(b, nInv);
}

jint OrgSpongycastleCryptoModesGcmGCMUtil_shiftRightNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint b = IOSIntArray_Get(nil_chk(x), 0);
  jint nInv = 32 - n;
  *IOSIntArray_GetRef(nil_chk(z), 0) = JreURShift32(b, n);
  jint c = JreLShift32(b, nInv);
  b = IOSIntArray_Get(x, 1);
  *IOSIntArray_GetRef(z, 1) = (JreURShift32(b, n)) | c;
  c = JreLShift32(b, nInv);
  b = IOSIntArray_Get(x, 2);
  *IOSIntArray_GetRef(z, 2) = (JreURShift32(b, n)) | c;
  c = JreLShift32(b, nInv);
  b = IOSIntArray_Get(x, 3);
  *IOSIntArray_GetRef(z, 3) = (JreURShift32(b, n)) | c;
  return JreLShift32(b, nInv);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_(IOSByteArray *x, IOSByteArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint i = 0;
  do {
    *IOSByteArray_GetRef(nil_chk(x), i) ^= IOSByteArray_Get(nil_chk(y), i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, i);
    ++i;
  }
  while (i < 16);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withInt_withInt_(IOSByteArray *x, IOSByteArray *y, jint yOff, jint yLen) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  while (--yLen >= 0) {
    *IOSByteArray_GetRef(nil_chk(x), yLen) ^= IOSByteArray_Get(nil_chk(y), yOff + yLen);
  }
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withByteArray_(IOSByteArray *x, IOSByteArray *y, IOSByteArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  jint i = 0;
  do {
    *IOSByteArray_GetRef(nil_chk(z), i) = (jbyte) (IOSByteArray_Get(nil_chk(x), i) ^ IOSByteArray_Get(nil_chk(y), i));
    ++i;
    *IOSByteArray_GetRef(z, i) = (jbyte) (IOSByteArray_Get(x, i) ^ IOSByteArray_Get(y, i));
    ++i;
    *IOSByteArray_GetRef(z, i) = (jbyte) (IOSByteArray_Get(x, i) ^ IOSByteArray_Get(y, i));
    ++i;
    *IOSByteArray_GetRef(z, i) = (jbyte) (IOSByteArray_Get(x, i) ^ IOSByteArray_Get(y, i));
    ++i;
  }
  while (i < 16);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  *IOSIntArray_GetRef(nil_chk(x), 0) ^= IOSIntArray_Get(nil_chk(y), 0);
  *IOSIntArray_GetRef(x, 1) ^= IOSIntArray_Get(y, 1);
  *IOSIntArray_GetRef(x, 2) ^= IOSIntArray_Get(y, 2);
  *IOSIntArray_GetRef(x, 3) ^= IOSIntArray_Get(y, 3);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  *IOSIntArray_GetRef(nil_chk(z), 0) = IOSIntArray_Get(nil_chk(x), 0) ^ IOSIntArray_Get(nil_chk(y), 0);
  *IOSIntArray_GetRef(z, 1) = IOSIntArray_Get(x, 1) ^ IOSIntArray_Get(y, 1);
  *IOSIntArray_GetRef(z, 2) = IOSIntArray_Get(x, 2) ^ IOSIntArray_Get(y, 2);
  *IOSIntArray_GetRef(z, 3) = IOSIntArray_Get(x, 3) ^ IOSIntArray_Get(y, 3);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  *IOSLongArray_GetRef(nil_chk(x), 0) ^= IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(x, 1) ^= IOSLongArray_Get(y, 1);
}

void OrgSpongycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  OrgSpongycastleCryptoModesGcmGCMUtil_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1) ^ IOSLongArray_Get(y, 1);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoModesGcmGCMUtil)