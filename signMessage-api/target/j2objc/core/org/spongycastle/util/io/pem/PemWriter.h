//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/io/pem/PemWriter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilIoPemPemWriter")
#ifdef RESTRICT_OrgSpongycastleUtilIoPemPemWriter
#define INCLUDE_ALL_OrgSpongycastleUtilIoPemPemWriter 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilIoPemPemWriter 1
#endif
#undef RESTRICT_OrgSpongycastleUtilIoPemPemWriter

#if !defined (OrgSpongycastleUtilIoPemPemWriter_) && (INCLUDE_ALL_OrgSpongycastleUtilIoPemPemWriter || defined(INCLUDE_OrgSpongycastleUtilIoPemPemWriter))
#define OrgSpongycastleUtilIoPemPemWriter_

#define RESTRICT_JavaIoBufferedWriter 1
#define INCLUDE_JavaIoBufferedWriter 1
#include "java/io/BufferedWriter.h"

@class JavaIoWriter;
@class OrgSpongycastleUtilIoPemPemObject;
@protocol OrgSpongycastleUtilIoPemPemObjectGenerator;

@interface OrgSpongycastleUtilIoPemPemWriter : JavaIoBufferedWriter

#pragma mark Public

- (instancetype)initWithJavaIoWriter:(JavaIoWriter *)outArg;

- (jint)getOutputSizeWithOrgSpongycastleUtilIoPemPemObject:(OrgSpongycastleUtilIoPemPemObject *)obj;

- (void)writeObjectWithOrgSpongycastleUtilIoPemPemObjectGenerator:(id<OrgSpongycastleUtilIoPemPemObjectGenerator>)objGen;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithJavaIoWriter:(JavaIoWriter *)arg0
                             withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleUtilIoPemPemWriter)

FOUNDATION_EXPORT void OrgSpongycastleUtilIoPemPemWriter_initWithJavaIoWriter_(OrgSpongycastleUtilIoPemPemWriter *self, JavaIoWriter *outArg);

FOUNDATION_EXPORT OrgSpongycastleUtilIoPemPemWriter *new_OrgSpongycastleUtilIoPemPemWriter_initWithJavaIoWriter_(JavaIoWriter *outArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilIoPemPemWriter *create_OrgSpongycastleUtilIoPemPemWriter_initWithJavaIoWriter_(JavaIoWriter *outArg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilIoPemPemWriter)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilIoPemPemWriter")
