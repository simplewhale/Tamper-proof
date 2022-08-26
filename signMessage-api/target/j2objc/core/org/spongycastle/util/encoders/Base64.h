//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/encoders/Base64.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilEncodersBase64")
#ifdef RESTRICT_OrgSpongycastleUtilEncodersBase64
#define INCLUDE_ALL_OrgSpongycastleUtilEncodersBase64 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilEncodersBase64 1
#endif
#undef RESTRICT_OrgSpongycastleUtilEncodersBase64

#if !defined (OrgSpongycastleUtilEncodersBase64_) && (INCLUDE_ALL_OrgSpongycastleUtilEncodersBase64 || defined(INCLUDE_OrgSpongycastleUtilEncodersBase64))
#define OrgSpongycastleUtilEncodersBase64_

@class IOSByteArray;
@class JavaIoOutputStream;

@interface OrgSpongycastleUtilEncodersBase64 : NSObject

#pragma mark Public

- (instancetype)init;

+ (IOSByteArray *)decodeWithByteArray:(IOSByteArray *)data;

+ (jint)decodeWithByteArray:(IOSByteArray *)base64Data
                    withInt:(jint)start
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

+ (IOSByteArray *)decodeWithNSString:(NSString *)data;

+ (jint)decodeWithNSString:(NSString *)data
    withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

+ (IOSByteArray *)encodeWithByteArray:(IOSByteArray *)data;

+ (IOSByteArray *)encodeWithByteArray:(IOSByteArray *)data
                              withInt:(jint)off
                              withInt:(jint)length;

+ (jint)encodeWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

+ (jint)encodeWithByteArray:(IOSByteArray *)data
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

+ (NSString *)toBase64StringWithByteArray:(IOSByteArray *)data;

+ (NSString *)toBase64StringWithByteArray:(IOSByteArray *)data
                                  withInt:(jint)off
                                  withInt:(jint)length;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleUtilEncodersBase64)

FOUNDATION_EXPORT void OrgSpongycastleUtilEncodersBase64_init(OrgSpongycastleUtilEncodersBase64 *self);

FOUNDATION_EXPORT OrgSpongycastleUtilEncodersBase64 *new_OrgSpongycastleUtilEncodersBase64_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilEncodersBase64 *create_OrgSpongycastleUtilEncodersBase64_init(void);

FOUNDATION_EXPORT NSString *OrgSpongycastleUtilEncodersBase64_toBase64StringWithByteArray_(IOSByteArray *data);

FOUNDATION_EXPORT NSString *OrgSpongycastleUtilEncodersBase64_toBase64StringWithByteArray_withInt_withInt_(IOSByteArray *data, jint off, jint length);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleUtilEncodersBase64_encodeWithByteArray_(IOSByteArray *data);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleUtilEncodersBase64_encodeWithByteArray_withInt_withInt_(IOSByteArray *data, jint off, jint length);

FOUNDATION_EXPORT jint OrgSpongycastleUtilEncodersBase64_encodeWithByteArray_withJavaIoOutputStream_(IOSByteArray *data, JavaIoOutputStream *outArg);

FOUNDATION_EXPORT jint OrgSpongycastleUtilEncodersBase64_encodeWithByteArray_withInt_withInt_withJavaIoOutputStream_(IOSByteArray *data, jint off, jint length, JavaIoOutputStream *outArg);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleUtilEncodersBase64_decodeWithByteArray_(IOSByteArray *data);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleUtilEncodersBase64_decodeWithNSString_(NSString *data);

FOUNDATION_EXPORT jint OrgSpongycastleUtilEncodersBase64_decodeWithNSString_withJavaIoOutputStream_(NSString *data, JavaIoOutputStream *outArg);

FOUNDATION_EXPORT jint OrgSpongycastleUtilEncodersBase64_decodeWithByteArray_withInt_withInt_withJavaIoOutputStream_(IOSByteArray *base64Data, jint start, jint length, JavaIoOutputStream *outArg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilEncodersBase64)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilEncodersBase64")
