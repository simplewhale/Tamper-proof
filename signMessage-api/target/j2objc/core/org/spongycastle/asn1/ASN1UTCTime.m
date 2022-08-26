//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ASN1UTCTime.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/text/ParseException.h"
#include "java/text/SimpleDateFormat.h"
#include "java/util/Date.h"
#include "java/util/Locale.h"
#include "java/util/SimpleTimeZone.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1OutputStream.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/ASN1UTCTime.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/StreamUtil.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/Strings.h"

@interface OrgSpongycastleAsn1ASN1UTCTime () {
 @public
  IOSByteArray *time_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1ASN1UTCTime, time_, IOSByteArray *)

@implementation OrgSpongycastleAsn1ASN1UTCTime

+ (OrgSpongycastleAsn1ASN1UTCTime *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1ASN1UTCTime_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1ASN1UTCTime *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                           withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1ASN1UTCTime_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithNSString:(NSString *)time {
  OrgSpongycastleAsn1ASN1UTCTime_initWithNSString_(self, time);
  return self;
}

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time {
  OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(self, time);
  return self;
}

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time
                  withJavaUtilLocale:(JavaUtilLocale *)locale {
  OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(self, time, locale);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)time {
  OrgSpongycastleAsn1ASN1UTCTime_initWithByteArray_(self, time);
  return self;
}

- (JavaUtilDate *)getDate {
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyMMddHHmmssz");
  return [dateF parseWithNSString:[self getTime]];
}

- (JavaUtilDate *)getAdjustedDate {
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmssz");
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  return [dateF parseWithNSString:[self getAdjustedTime]];
}

- (NSString *)getTime {
  NSString *stime = OrgSpongycastleUtilStrings_fromByteArrayWithByteArray_(time_);
  if ([((NSString *) nil_chk(stime)) java_indexOf:'-'] < 0 && [stime java_indexOf:'+'] < 0) {
    if ([stime java_length] == 11) {
      return JreStrcat("$$", [stime java_substring:0 endIndex:10], @"00GMT+00:00");
    }
    else {
      return JreStrcat("$$", [stime java_substring:0 endIndex:12], @"GMT+00:00");
    }
  }
  else {
    jint index = [stime java_indexOf:'-'];
    if (index < 0) {
      index = [stime java_indexOf:'+'];
    }
    NSString *d = stime;
    if (index == [stime java_length] - 3) {
      (void) JreStrAppendStrong(&d, "$", @"00");
    }
    if (index == 10) {
      return JreStrcat("$$$C$", [d java_substring:0 endIndex:10], @"00GMT", [d java_substring:10 endIndex:13], ':', [d java_substring:13 endIndex:15]);
    }
    else {
      return JreStrcat("$$$C$", [d java_substring:0 endIndex:12], @"GMT", [d java_substring:12 endIndex:15], ':', [d java_substring:15 endIndex:17]);
    }
  }
}

- (NSString *)getAdjustedTime {
  NSString *d = [self getTime];
  if ([((NSString *) nil_chk(d)) charAtWithInt:0] < '5') {
    return JreStrcat("$$", @"20", d);
  }
  else {
    return JreStrcat("$$", @"19", d);
  }
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  jint length = ((IOSByteArray *) nil_chk(time_))->size_;
  return 1 + OrgSpongycastleAsn1StreamUtil_calculateBodyLengthWithInt_(length) + length;
}

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg {
  [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeWithInt:OrgSpongycastleAsn1BERTags_UTC_TIME];
  jint length = ((IOSByteArray *) nil_chk(time_))->size_;
  [outArg writeLengthWithInt:length];
  for (jint i = 0; i != length; i++) {
    [outArg writeWithInt:(jbyte) IOSByteArray_Get(nil_chk(time_), i)];
  }
}

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1ASN1UTCTime class]])) {
    return false;
  }
  return OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_(time_, ((OrgSpongycastleAsn1ASN1UTCTime *) nil_chk(((OrgSpongycastleAsn1ASN1UTCTime *) cast_chk(o, [OrgSpongycastleAsn1ASN1UTCTime class]))))->time_);
}

- (NSUInteger)hash {
  return OrgSpongycastleUtilArrays_hashCodeWithByteArray_(time_);
}

- (NSString *)description {
  return OrgSpongycastleUtilStrings_fromByteArrayWithByteArray_(time_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1ASN1UTCTime;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1UTCTime;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 6, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 8, 9, 10, -1, -1, -1 },
    { NULL, "Z", 0x0, 11, 12, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 13, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 14, -1, -1, -1, -1, -1 },
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
  methods[6].selector = @selector(getDate);
  methods[7].selector = @selector(getAdjustedDate);
  methods[8].selector = @selector(getTime);
  methods[9].selector = @selector(getAdjustedTime);
  methods[10].selector = @selector(isConstructed);
  methods[11].selector = @selector(encodedLength);
  methods[12].selector = @selector(encodeWithOrgSpongycastleAsn1ASN1OutputStream:);
  methods[13].selector = @selector(asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[14].selector = @selector(hash);
  methods[15].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "time_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSString;", "LJavaUtilDate;", "LJavaUtilDate;LJavaUtilLocale;", "[B", "LJavaTextParseException;", "encode", "LOrgSpongycastleAsn1ASN1OutputStream;", "LJavaIoIOException;", "asn1Equals", "LOrgSpongycastleAsn1ASN1Primitive;", "hashCode", "toString" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1ASN1UTCTime = { "ASN1UTCTime", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 16, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1ASN1UTCTime;
}

@end

OrgSpongycastleAsn1ASN1UTCTime *OrgSpongycastleAsn1ASN1UTCTime_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1ASN1UTCTime_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1ASN1UTCTime class]]) {
    return (OrgSpongycastleAsn1ASN1UTCTime *) cast_chk(obj, [OrgSpongycastleAsn1ASN1UTCTime class]);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return (OrgSpongycastleAsn1ASN1UTCTime *) cast_chk(OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])), [OrgSpongycastleAsn1ASN1UTCTime class]);
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"encoding error in getInstance: ", [e description]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

OrgSpongycastleAsn1ASN1UTCTime *OrgSpongycastleAsn1ASN1UTCTime_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1ASN1UTCTime_initialize();
  OrgSpongycastleAsn1ASN1Object *o = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
  if (explicit_ || [o isKindOfClass:[OrgSpongycastleAsn1ASN1UTCTime class]]) {
    return OrgSpongycastleAsn1ASN1UTCTime_getInstanceWithId_(o);
  }
  else {
    return new_OrgSpongycastleAsn1ASN1UTCTime_initWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(((OrgSpongycastleAsn1ASN1OctetString *) cast_chk(o, [OrgSpongycastleAsn1ASN1OctetString class])))) getOctets]);
  }
}

void OrgSpongycastleAsn1ASN1UTCTime_initWithNSString_(OrgSpongycastleAsn1ASN1UTCTime *self, NSString *time) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->time_ = OrgSpongycastleUtilStrings_toByteArrayWithNSString_(time);
  @try {
    (void) [self getDate];
  }
  @catch (JavaTextParseException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"invalid date string: ", [e getMessage]));
  }
}

OrgSpongycastleAsn1ASN1UTCTime *new_OrgSpongycastleAsn1ASN1UTCTime_initWithNSString_(NSString *time) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithNSString_, time)
}

OrgSpongycastleAsn1ASN1UTCTime *create_OrgSpongycastleAsn1ASN1UTCTime_initWithNSString_(NSString *time) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithNSString_, time)
}

void OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(OrgSpongycastleAsn1ASN1UTCTime *self, JavaUtilDate *time) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyMMddHHmmss'Z'");
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  self->time_ = OrgSpongycastleUtilStrings_toByteArrayWithNSString_([dateF formatWithJavaUtilDate:time]);
}

OrgSpongycastleAsn1ASN1UTCTime *new_OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(JavaUtilDate *time) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithJavaUtilDate_, time)
}

OrgSpongycastleAsn1ASN1UTCTime *create_OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(JavaUtilDate *time) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithJavaUtilDate_, time)
}

void OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(OrgSpongycastleAsn1ASN1UTCTime *self, JavaUtilDate *time, JavaUtilLocale *locale) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_withJavaUtilLocale_(@"yyMMddHHmmss'Z'", locale);
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  self->time_ = OrgSpongycastleUtilStrings_toByteArrayWithNSString_([dateF formatWithJavaUtilDate:time]);
}

OrgSpongycastleAsn1ASN1UTCTime *new_OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithJavaUtilDate_withJavaUtilLocale_, time, locale)
}

OrgSpongycastleAsn1ASN1UTCTime *create_OrgSpongycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithJavaUtilDate_withJavaUtilLocale_, time, locale)
}

void OrgSpongycastleAsn1ASN1UTCTime_initWithByteArray_(OrgSpongycastleAsn1ASN1UTCTime *self, IOSByteArray *time) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->time_ = time;
}

OrgSpongycastleAsn1ASN1UTCTime *new_OrgSpongycastleAsn1ASN1UTCTime_initWithByteArray_(IOSByteArray *time) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithByteArray_, time)
}

OrgSpongycastleAsn1ASN1UTCTime *create_OrgSpongycastleAsn1ASN1UTCTime_initWithByteArray_(IOSByteArray *time) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1ASN1UTCTime, initWithByteArray_, time)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1ASN1UTCTime)
