//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSUtil.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/ObjectInputStream.h"
#include "java/io/ObjectOutputStream.h"
#include "java/io/PrintStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Math.h"
#include "java/lang/NullPointerException.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSUtil.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/encoders/Hex.h"

@implementation OrgSpongycastlePqcCryptoXmssXMSSUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)log2WithInt:(jint)n {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_(n);
}

+ (IOSByteArray *)toBytesBigEndianWithLong:(jlong)value
                                   withInt:(jint)sizeInByte {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(value, sizeInByte);
}

+ (void)longToBigEndianWithLong:(jlong)value
                  withByteArray:(IOSByteArray *)inArg
                        withInt:(jint)offset {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_longToBigEndianWithLong_withByteArray_withInt_(value, inArg, offset);
}

+ (jlong)bytesToXBigEndianWithByteArray:(IOSByteArray *)inArg
                                withInt:(jint)offset
                                withInt:(jint)size {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_bytesToXBigEndianWithByteArray_withInt_withInt_(inArg, offset, size);
}

+ (IOSByteArray *)cloneArrayWithByteArray:(IOSByteArray *)inArg {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(inArg);
}

+ (IOSObjectArray *)cloneArrayWithByteArray2:(IOSObjectArray *)inArg {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray2_(inArg);
}

+ (jboolean)areEqualWithByteArray2:(IOSObjectArray *)a
                    withByteArray2:(IOSObjectArray *)b {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_areEqualWithByteArray2_withByteArray2_(a, b);
}

+ (void)dumpByteArrayWithByteArray2:(IOSObjectArray *)x {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_dumpByteArrayWithByteArray2_(x);
}

+ (jboolean)hasNullPointerWithByteArray2:(IOSObjectArray *)inArg {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(inArg);
}

+ (void)copyBytesAtOffsetWithByteArray:(IOSByteArray *)dst
                         withByteArray:(IOSByteArray *)src
                               withInt:(jint)offset {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(dst, src, offset);
}

+ (IOSByteArray *)extractBytesAtOffsetWithByteArray:(IOSByteArray *)src
                                            withInt:(jint)offset
                                            withInt:(jint)length {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(src, offset, length);
}

+ (jboolean)isIndexValidWithInt:(jint)height
                       withLong:(jlong)index {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_isIndexValidWithInt_withLong_(height, index);
}

+ (jint)getDigestSizeWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_getDigestSizeWithOrgSpongycastleCryptoDigest_(digest);
}

+ (jlong)getTreeIndexWithLong:(jlong)index
                      withInt:(jint)xmssTreeHeight {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_getTreeIndexWithLong_withInt_(index, xmssTreeHeight);
}

+ (jint)getLeafIndexWithLong:(jlong)index
                     withInt:(jint)xmssTreeHeight {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(index, xmssTreeHeight);
}

+ (IOSByteArray *)serializeWithId:(id)obj {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_serializeWithId_(obj);
}

+ (id)deserializeWithByteArray:(IOSByteArray *)data {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_deserializeWithByteArray_(data);
}

+ (jint)calculateTauWithInt:(jint)index
                    withInt:(jint)height {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_calculateTauWithInt_withInt_(index, height);
}

+ (jboolean)isNewBDSInitNeededWithLong:(jlong)globalIndex
                               withInt:(jint)xmssHeight
                               withInt:(jint)layer {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_isNewBDSInitNeededWithLong_withInt_withInt_(globalIndex, xmssHeight, layer);
}

+ (jboolean)isNewAuthenticationPathNeededWithLong:(jlong)globalIndex
                                          withInt:(jint)xmssHeight
                                          withInt:(jint)layer {
  return OrgSpongycastlePqcCryptoXmssXMSSUtil_isNewAuthenticationPathNeededWithLong_withInt_withInt_(globalIndex, xmssHeight, layer);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 8, 9, -1, -1, -1, -1 },
    { NULL, "[[B", 0x9, 8, 10, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 13, 10, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 14, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 16, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 17, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 18, 19, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 20, 21, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 22, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 23, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 24, 25, 26, -1, -1, -1 },
    { NULL, "LNSObject;", 0x9, 27, 9, 28, -1, -1, -1 },
    { NULL, "I", 0x9, 29, 30, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 31, 32, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 33, 32, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(log2WithInt:);
  methods[2].selector = @selector(toBytesBigEndianWithLong:withInt:);
  methods[3].selector = @selector(longToBigEndianWithLong:withByteArray:withInt:);
  methods[4].selector = @selector(bytesToXBigEndianWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(cloneArrayWithByteArray:);
  methods[6].selector = @selector(cloneArrayWithByteArray2:);
  methods[7].selector = @selector(areEqualWithByteArray2:withByteArray2:);
  methods[8].selector = @selector(dumpByteArrayWithByteArray2:);
  methods[9].selector = @selector(hasNullPointerWithByteArray2:);
  methods[10].selector = @selector(copyBytesAtOffsetWithByteArray:withByteArray:withInt:);
  methods[11].selector = @selector(extractBytesAtOffsetWithByteArray:withInt:withInt:);
  methods[12].selector = @selector(isIndexValidWithInt:withLong:);
  methods[13].selector = @selector(getDigestSizeWithOrgSpongycastleCryptoDigest:);
  methods[14].selector = @selector(getTreeIndexWithLong:withInt:);
  methods[15].selector = @selector(getLeafIndexWithLong:withInt:);
  methods[16].selector = @selector(serializeWithId:);
  methods[17].selector = @selector(deserializeWithByteArray:);
  methods[18].selector = @selector(calculateTauWithInt:withInt:);
  methods[19].selector = @selector(isNewBDSInitNeededWithLong:withInt:withInt:);
  methods[20].selector = @selector(isNewAuthenticationPathNeededWithLong:withInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "log2", "I", "toBytesBigEndian", "JI", "longToBigEndian", "J[BI", "bytesToXBigEndian", "[BII", "cloneArray", "[B", "[[B", "areEqual", "[[B[[B", "dumpByteArray", "hasNullPointer", "copyBytesAtOffset", "[B[BI", "extractBytesAtOffset", "isIndexValid", "IJ", "getDigestSize", "LOrgSpongycastleCryptoDigest;", "getTreeIndex", "getLeafIndex", "serialize", "LNSObject;", "LJavaIoIOException;", "deserialize", "LJavaIoIOException;LJavaLangClassNotFoundException;", "calculateTau", "II", "isNewBDSInitNeeded", "JII", "isNewAuthenticationPathNeeded" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssXMSSUtil = { "XMSSUtil", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, NULL, 7, 0x1, 21, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssXMSSUtil;
}

@end

void OrgSpongycastlePqcCryptoXmssXMSSUtil_init(OrgSpongycastlePqcCryptoXmssXMSSUtil *self) {
  NSObject_init(self);
}

OrgSpongycastlePqcCryptoXmssXMSSUtil *new_OrgSpongycastlePqcCryptoXmssXMSSUtil_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssXMSSUtil, init)
}

OrgSpongycastlePqcCryptoXmssXMSSUtil *create_OrgSpongycastlePqcCryptoXmssXMSSUtil_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssXMSSUtil, init)
}

jint OrgSpongycastlePqcCryptoXmssXMSSUtil_log2WithInt_(jint n) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  jint log = 0;
  while ((JreRShiftAssignInt(&n, 1)) != 0) {
    log++;
  }
  return log;
}

IOSByteArray *OrgSpongycastlePqcCryptoXmssXMSSUtil_toBytesBigEndianWithLong_withInt_(jlong value, jint sizeInByte) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  IOSByteArray *out = [IOSByteArray newArrayWithLength:sizeInByte];
  for (jint i = (sizeInByte - 1); i >= 0; i--) {
    *IOSByteArray_GetRef(out, i) = (jbyte) value;
    JreURShiftAssignLong(&value, 8);
  }
  return out;
}

void OrgSpongycastlePqcCryptoXmssXMSSUtil_longToBigEndianWithLong_withByteArray_withInt_(jlong value, IOSByteArray *inArg, jint offset) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (inArg == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"in == null");
  }
  if ((inArg->size_ - offset) < 8) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"not enough space in array");
  }
  *IOSByteArray_GetRef(inArg, offset) = (jbyte) ((JreRShift64(value, 56)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 1) = (jbyte) ((JreRShift64(value, 48)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 2) = (jbyte) ((JreRShift64(value, 40)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 3) = (jbyte) ((JreRShift64(value, 32)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 4) = (jbyte) ((JreRShift64(value, 24)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 5) = (jbyte) ((JreRShift64(value, 16)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 6) = (jbyte) ((JreRShift64(value, 8)) & (jint) 0xff);
  *IOSByteArray_GetRef(inArg, offset + 7) = (jbyte) ((value) & (jint) 0xff);
}

jlong OrgSpongycastlePqcCryptoXmssXMSSUtil_bytesToXBigEndianWithByteArray_withInt_withInt_(IOSByteArray *inArg, jint offset, jint size) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (inArg == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"in == null");
  }
  jlong res = 0;
  for (jint i = offset; i < (offset + size); i++) {
    res = (JreLShift64(res, 8)) | (IOSByteArray_Get(inArg, i) & (jint) 0xff);
  }
  return res;
}

IOSByteArray *OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(IOSByteArray *inArg) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (inArg == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"in == null");
  }
  IOSByteArray *out = [IOSByteArray newArrayWithLength:inArg->size_];
  for (jint i = 0; i < inArg->size_; i++) {
    *IOSByteArray_GetRef(out, i) = IOSByteArray_Get(inArg, i);
  }
  return out;
}

IOSObjectArray *OrgSpongycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray2_(IOSObjectArray *inArg) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (OrgSpongycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(inArg)) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"in has null pointers");
  }
  IOSObjectArray *out = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(inArg))->size_ type:IOSClass_byteArray(1)];
  for (jint i = 0; i < inArg->size_; i++) {
    (void) IOSObjectArray_SetAndConsume(out, i, [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(IOSObjectArray_Get(inArg, i)))->size_]);
    for (jint j = 0; j < ((IOSByteArray *) nil_chk(IOSObjectArray_Get(inArg, i)))->size_; j++) {
      *IOSByteArray_GetRef(nil_chk(IOSObjectArray_Get(out, i)), j) = IOSByteArray_Get(nil_chk(IOSObjectArray_Get(inArg, i)), j);
    }
  }
  return out;
}

jboolean OrgSpongycastlePqcCryptoXmssXMSSUtil_areEqualWithByteArray2_withByteArray2_(IOSObjectArray *a, IOSObjectArray *b) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (OrgSpongycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(a) || OrgSpongycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(b)) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"a or b == null");
  }
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(a))->size_; i++) {
    if (!OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_(IOSObjectArray_Get(a, i), IOSObjectArray_Get(nil_chk(b), i))) {
      return false;
    }
  }
  return true;
}

void OrgSpongycastlePqcCryptoXmssXMSSUtil_dumpByteArrayWithByteArray2_(IOSObjectArray *x) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (OrgSpongycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(x)) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"x has null pointers");
  }
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(x))->size_; i++) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, out))) printlnWithNSString:OrgSpongycastleUtilEncodersHex_toHexStringWithByteArray_(IOSObjectArray_Get(x, i))];
  }
}

jboolean OrgSpongycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(IOSObjectArray *inArg) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (inArg == nil) {
    return true;
  }
  for (jint i = 0; i < inArg->size_; i++) {
    if (IOSObjectArray_Get(inArg, i) == nil) {
      return true;
    }
  }
  return false;
}

void OrgSpongycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(IOSByteArray *dst, IOSByteArray *src, jint offset) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (dst == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"dst == null");
  }
  if (src == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"src == null");
  }
  if (offset < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"offset hast to be >= 0");
  }
  if ((src->size_ + offset) > dst->size_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"src length + offset must not be greater than size of destination");
  }
  for (jint i = 0; i < src->size_; i++) {
    *IOSByteArray_GetRef(dst, offset + i) = IOSByteArray_Get(src, i);
  }
}

IOSByteArray *OrgSpongycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(IOSByteArray *src, jint offset, jint length) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (src == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"src == null");
  }
  if (offset < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"offset hast to be >= 0");
  }
  if (length < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"length hast to be >= 0");
  }
  if ((offset + length) > src->size_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"offset + length must not be greater then size of source array");
  }
  IOSByteArray *out = [IOSByteArray newArrayWithLength:length];
  for (jint i = 0; i < out->size_; i++) {
    *IOSByteArray_GetRef(out, i) = IOSByteArray_Get(src, offset + i);
  }
  return out;
}

jboolean OrgSpongycastlePqcCryptoXmssXMSSUtil_isIndexValidWithInt_withLong_(jint height, jlong index) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (index < 0) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"index must not be negative");
  }
  return index < (JreLShift64(1LL, height));
}

jint OrgSpongycastlePqcCryptoXmssXMSSUtil_getDigestSizeWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (digest == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"digest == null");
  }
  NSString *algorithmName = [digest getAlgorithmName];
  if ([((NSString *) nil_chk(algorithmName)) isEqual:@"SHAKE128"]) {
    return 32;
  }
  if ([algorithmName isEqual:@"SHAKE256"]) {
    return 64;
  }
  return [digest getDigestSize];
}

jlong OrgSpongycastlePqcCryptoXmssXMSSUtil_getTreeIndexWithLong_withInt_(jlong index, jint xmssTreeHeight) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  return JreRShift64(index, xmssTreeHeight);
}

jint OrgSpongycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(jlong index, jint xmssTreeHeight) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  return (jint) (index & ((JreLShift64(1LL, xmssTreeHeight)) - 1LL));
}

IOSByteArray *OrgSpongycastlePqcCryptoXmssXMSSUtil_serializeWithId_(id obj) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  JavaIoByteArrayOutputStream *out = new_JavaIoByteArrayOutputStream_init();
  JavaIoObjectOutputStream *oos = new_JavaIoObjectOutputStream_initWithJavaIoOutputStream_(out);
  [oos writeObjectWithId:obj];
  [oos flush];
  return [out toByteArray];
}

id OrgSpongycastlePqcCryptoXmssXMSSUtil_deserializeWithByteArray_(IOSByteArray *data) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  JavaIoByteArrayInputStream *in = new_JavaIoByteArrayInputStream_initWithByteArray_(data);
  JavaIoObjectInputStream *is = new_JavaIoObjectInputStream_initWithJavaIoInputStream_(in);
  return [is readObject];
}

jint OrgSpongycastlePqcCryptoXmssXMSSUtil_calculateTauWithInt_withInt_(jint index, jint height) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  jint tau = 0;
  for (jint i = 0; i < height; i++) {
    if (((JreRShift32(index, i)) & 1) == 0) {
      tau = i;
      break;
    }
  }
  return tau;
}

jboolean OrgSpongycastlePqcCryptoXmssXMSSUtil_isNewBDSInitNeededWithLong_withInt_withInt_(jlong globalIndex, jint xmssHeight, jint layer) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (globalIndex == 0) {
    return false;
  }
  return (globalIndex % JreFpToLong(JavaLangMath_powWithDouble_withDouble_((JreLShift32(1, xmssHeight)), layer + 1)) == 0) ? true : false;
}

jboolean OrgSpongycastlePqcCryptoXmssXMSSUtil_isNewAuthenticationPathNeededWithLong_withInt_withInt_(jlong globalIndex, jint xmssHeight, jint layer) {
  OrgSpongycastlePqcCryptoXmssXMSSUtil_initialize();
  if (globalIndex == 0) {
    return false;
  }
  return ((globalIndex + 1) % JreFpToLong(JavaLangMath_powWithDouble_withDouble_((JreLShift32(1, xmssHeight)), layer)) == 0) ? true : false;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssXMSSUtil)
