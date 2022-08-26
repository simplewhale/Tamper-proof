//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ASN1GeneralizedTime.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/text/ParseException.h"
#include "java/text/SimpleDateFormat.h"
#include "java/util/Date.h"
#include "java/util/Locale.h"
#include "java/util/SimpleTimeZone.h"
#include "java/util/TimeZone.h"
#include "org/spongycastle/asn1/ASN1GeneralizedTime.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1OutputStream.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/StreamUtil.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/Strings.h"

@interface OrgSpongycastleAsn1ASN1GeneralizedTime () {
 @public
  IOSByteArray *time_;
}

- (NSString *)calculateGMTOffset;

- (NSString *)convertWithInt:(jint)time;

- (jboolean)hasFractionalSeconds;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1ASN1GeneralizedTime, time_, IOSByteArray *)

__attribute__((unused)) static NSString *OrgSpongycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(OrgSpongycastleAsn1ASN1GeneralizedTime *self);

__attribute__((unused)) static NSString *OrgSpongycastleAsn1ASN1GeneralizedTime_convertWithInt_(OrgSpongycastleAsn1ASN1GeneralizedTime *self, jint time);

__attribute__((unused)) static jboolean OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(OrgSpongycastleAsn1ASN1GeneralizedTime *self);

@implementation OrgSpongycastleAsn1ASN1GeneralizedTime

+ (OrgSpongycastleAsn1ASN1GeneralizedTime *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1ASN1GeneralizedTime *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                   withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithNSString:(NSString *)time {
  OrgSpongycastleAsn1ASN1GeneralizedTime_initWithNSString_(self, time);
  return self;
}

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time {
  OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(self, time);
  return self;
}

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time
                  withJavaUtilLocale:(JavaUtilLocale *)locale {
  OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(self, time, locale);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)bytes {
  OrgSpongycastleAsn1ASN1GeneralizedTime_initWithByteArray_(self, bytes);
  return self;
}

- (NSString *)getTimeString {
  return OrgSpongycastleUtilStrings_fromByteArrayWithByteArray_(time_);
}

- (NSString *)getTime {
  NSString *stime = OrgSpongycastleUtilStrings_fromByteArrayWithByteArray_(time_);
  if ([((NSString *) nil_chk(stime)) charAtWithInt:[stime java_length] - 1] == 'Z') {
    return JreStrcat("$$", [stime java_substring:0 endIndex:[stime java_length] - 1], @"GMT+00:00");
  }
  else {
    jint signPos = [stime java_length] - 5;
    jchar sign = [stime charAtWithInt:signPos];
    if (sign == '-' || sign == '+') {
      return JreStrcat("$$$C$", [stime java_substring:0 endIndex:signPos], @"GMT", [stime java_substring:signPos endIndex:signPos + 3], ':', [stime java_substring:signPos + 3]);
    }
    else {
      signPos = [stime java_length] - 3;
      sign = [stime charAtWithInt:signPos];
      if (sign == '-' || sign == '+') {
        return JreStrcat("$$$$", [stime java_substring:0 endIndex:signPos], @"GMT", [stime java_substring:signPos], @":00");
      }
    }
  }
  return JreStrcat("$$", stime, OrgSpongycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(self));
}

- (NSString *)calculateGMTOffset {
  return OrgSpongycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(self);
}

- (NSString *)convertWithInt:(jint)time {
  return OrgSpongycastleAsn1ASN1GeneralizedTime_convertWithInt_(self, time);
}

- (JavaUtilDate *)getDate {
  JavaTextSimpleDateFormat *dateF;
  NSString *stime = OrgSpongycastleUtilStrings_fromByteArrayWithByteArray_(time_);
  NSString *d = stime;
  if ([((NSString *) nil_chk(stime)) java_hasSuffix:@"Z"]) {
    if (OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(self)) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss.SSS'Z'");
    }
    else {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss'Z'");
    }
    [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  }
  else if ([stime java_indexOf:'-'] > 0 || [stime java_indexOf:'+'] > 0) {
    d = [self getTime];
    if (OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(self)) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss.SSSz");
    }
    else {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmssz");
    }
    [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  }
  else {
    if (OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(self)) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss.SSS");
    }
    else {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss");
    }
    [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, [((JavaUtilTimeZone *) nil_chk(JavaUtilTimeZone_getDefault())) getID])];
  }
  if (OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(self)) {
    NSString *frac = [((NSString *) nil_chk(d)) java_substring:14];
    jint index;
    for (index = 1; index < [((NSString *) nil_chk(frac)) java_length]; index++) {
      jchar ch = [frac charAtWithInt:index];
      if (!('0' <= ch && ch <= '9')) {
        break;
      }
    }
    if (index - 1 > 3) {
      frac = JreStrcat("$$", [frac java_substring:0 endIndex:4], [frac java_substring:index]);
      d = JreStrcat("$$", [d java_substring:0 endIndex:14], frac);
    }
    else if (index - 1 == 1) {
      frac = JreStrcat("$$$", [frac java_substring:0 endIndex:index], @"00", [frac java_substring:index]);
      d = JreStrcat("$$", [d java_substring:0 endIndex:14], frac);
    }
    else if (index - 1 == 2) {
      frac = JreStrcat("$C$", [frac java_substring:0 endIndex:index], '0', [frac java_substring:index]);
      d = JreStrcat("$$", [d java_substring:0 endIndex:14], frac);
    }
  }
  return [dateF parseWithNSString:d];
}

- (jboolean)hasFractionalSeconds {
  return OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(self);
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  jint length = ((IOSByteArray *) nil_chk(time_))->size_;
  return 1 + OrgSpongycastleAsn1StreamUtil_calculateBodyLengthWithInt_(length) + length;
}

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg {
  [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:OrgSpongycastleAsn1BERTags_GENERALIZED_TIME withByteArray:time_];
}

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1ASN1GeneralizedTime class]])) {
    return false;
  }
  return OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_(time_, ((OrgSpongycastleAsn1ASN1GeneralizedTime *) nil_chk(((OrgSpongycastleAsn1ASN1GeneralizedTime *) cast_chk(o, [OrgSpongycastleAsn1ASN1GeneralizedTime class]))))->time_);
}

- (NSUInteger)hash {
  return OrgSpongycastleUtilArrays_hashCodeWithByteArray_(time_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1ASN1GeneralizedTime;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1GeneralizedTime;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 6, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x2, 7, 8, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, 9, -1, -1, -1 },
    { NULL, "Z", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 10, 11, 12, -1, -1, -1 },
    { NULL, "Z", 0x0, 13, 14, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 15, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithNSString:);
  methods[3].selector = @selector(initWithJavaUtilDate:);
  methods[4].selector = @selector(initWithJavaUtilDate:withJavaUtilLocale:);
  methods[5].selector = @selector(initWithByteArray:);
  methods[6].selector = @selector(getTimeString);
  methods[7].selector = @selector(getTime);
  methods[8].selector = @selector(calculateGMTOffset);
  methods[9].selector = @selector(convertWithInt:);
  methods[10].selector = @selector(getDate);
  methods[11].selector = @selector(hasFractionalSeconds);
  methods[12].selector = @selector(isConstructed);
  methods[13].selector = @selector(encodedLength);
  methods[14].selector = @selector(encodeWithOrgSpongycastleAsn1ASN1OutputStream:);
  methods[15].selector = @selector(asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[16].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "time_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSString;", "LJavaUtilDate;", "LJavaUtilDate;LJavaUtilLocale;", "[B", "convert", "I", "LJavaTextParseException;", "encode", "LOrgSpongycastleAsn1ASN1OutputStream;", "LJavaIoIOException;", "asn1Equals", "LOrgSpongycastleAsn1ASN1Primitive;", "hashCode" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1ASN1GeneralizedTime = { "ASN1GeneralizedTime", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 17, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1ASN1GeneralizedTime;
}

@end

OrgSpongycastleAsn1ASN1GeneralizedTime *OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1ASN1GeneralizedTime_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1ASN1GeneralizedTime class]]) {
    return (OrgSpongycastleAsn1ASN1GeneralizedTime *) cast_chk(obj, [OrgSpongycastleAsn1ASN1GeneralizedTime class]);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return (OrgSpongycastleAsn1ASN1GeneralizedTime *) cast_chk(OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])), [OrgSpongycastleAsn1ASN1GeneralizedTime class]);
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"encoding error in getInstance: ", [e description]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

OrgSpongycastleAsn1ASN1GeneralizedTime *OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1ASN1GeneralizedTime_initialize();
  OrgSpongycastleAsn1ASN1Primitive *o = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
  if (explicit_ || [o isKindOfClass:[OrgSpongycastleAsn1ASN1GeneralizedTime class]]) {
    return OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(o);
  }
  else {
    return new_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(((OrgSpongycastleAsn1ASN1OctetString *) cast_chk(o, [OrgSpongycastleAsn1ASN1OctetString class])))) getOctets]);
  }
}

void OrgSpongycastleAsn1ASN1GeneralizedTime_initWithNSString_(OrgSpongycastleAsn1ASN1GeneralizedTime *self, NSString *time) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->time_ = OrgSpongycastleUtilStrings_toByteArrayWithNSString_(time);
  @try {
    (void) [self getDate];
  }
  @catch (JavaTextParseException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"invalid date string: ", [e getMessage]));
  }
}

OrgSpongycastleAsn1ASN1GeneralizedTime *new_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithNSString_(NSString *time) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithNSString_, time)
}

OrgSpongycastleAsn1ASN1GeneralizedTime *create_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithNSString_(NSString *time) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithNSString_, time)
}

void OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(OrgSpongycastleAsn1ASN1GeneralizedTime *self, JavaUtilDate *time) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss'Z'");
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  self->time_ = OrgSpongycastleUtilStrings_toByteArrayWithNSString_([dateF formatWithJavaUtilDate:time]);
}

OrgSpongycastleAsn1ASN1GeneralizedTime *new_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(JavaUtilDate *time) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_, time)
}

OrgSpongycastleAsn1ASN1GeneralizedTime *create_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(JavaUtilDate *time) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_, time)
}

void OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(OrgSpongycastleAsn1ASN1GeneralizedTime *self, JavaUtilDate *time, JavaUtilLocale *locale) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_withJavaUtilLocale_(@"yyyyMMddHHmmss'Z'", locale);
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  self->time_ = OrgSpongycastleUtilStrings_toByteArrayWithNSString_([dateF formatWithJavaUtilDate:time]);
}

OrgSpongycastleAsn1ASN1GeneralizedTime *new_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_withJavaUtilLocale_, time, locale)
}

OrgSpongycastleAsn1ASN1GeneralizedTime *create_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_withJavaUtilLocale_, time, locale)
}

void OrgSpongycastleAsn1ASN1GeneralizedTime_initWithByteArray_(OrgSpongycastleAsn1ASN1GeneralizedTime *self, IOSByteArray *bytes) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->time_ = bytes;
}

OrgSpongycastleAsn1ASN1GeneralizedTime *new_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithByteArray_, bytes)
}

OrgSpongycastleAsn1ASN1GeneralizedTime *create_OrgSpongycastleAsn1ASN1GeneralizedTime_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1GeneralizedTime, initWithByteArray_, bytes)
}

NSString *OrgSpongycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(OrgSpongycastleAsn1ASN1GeneralizedTime *self) {
  NSString *sign = @"+";
  JavaUtilTimeZone *timeZone = JavaUtilTimeZone_getDefault();
  jint offset = [((JavaUtilTimeZone *) nil_chk(timeZone)) getRawOffset];
  if (offset < 0) {
    sign = @"-";
    offset = -offset;
  }
  jint hours = offset / (60 * 60 * 1000);
  jint minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);
  @try {
    if ([timeZone useDaylightTime] && [timeZone inDaylightTimeWithJavaUtilDate:[self getDate]]) {
      hours += [sign isEqual:@"+"] ? 1 : -1;
    }
  }
  @catch (JavaTextParseException *e) {
  }
  return JreStrcat("$$$C$", @"GMT", sign, OrgSpongycastleAsn1ASN1GeneralizedTime_convertWithInt_(self, hours), ':', OrgSpongycastleAsn1ASN1GeneralizedTime_convertWithInt_(self, minutes));
}

NSString *OrgSpongycastleAsn1ASN1GeneralizedTime_convertWithInt_(OrgSpongycastleAsn1ASN1GeneralizedTime *self, jint time) {
  if (time < 10) {
    return JreStrcat("CI", '0', time);
  }
  return JavaLangInteger_toStringWithInt_(time);
}

jboolean OrgSpongycastleAsn1ASN1GeneralizedTime_hasFractionalSeconds(OrgSpongycastleAsn1ASN1GeneralizedTime *self) {
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(self->time_))->size_; i++) {
    if (IOSByteArray_Get(self->time_, i) == '.') {
      if (i == 14) {
        return true;
      }
    }
  }
  return false;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1ASN1GeneralizedTime)
