//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/test/SimpleTest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilTestSimpleTest")
#ifdef RESTRICT_OrgSpongycastleUtilTestSimpleTest
#define INCLUDE_ALL_OrgSpongycastleUtilTestSimpleTest 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilTestSimpleTest 1
#endif
#undef RESTRICT_OrgSpongycastleUtilTestSimpleTest

#if !defined (OrgSpongycastleUtilTestSimpleTest_) && (INCLUDE_ALL_OrgSpongycastleUtilTestSimpleTest || defined(INCLUDE_OrgSpongycastleUtilTestSimpleTest))
#define OrgSpongycastleUtilTestSimpleTest_

#define RESTRICT_OrgSpongycastleUtilTestTest 1
#define INCLUDE_OrgSpongycastleUtilTestTest 1
#include "org/spongycastle/util/test/Test.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaIoPrintStream;
@class JavaLangThrowable;
@protocol OrgSpongycastleUtilTestTestResult;

@interface OrgSpongycastleUtilTestSimpleTest : NSObject < OrgSpongycastleUtilTestTest >

#pragma mark Public

- (instancetype)init;

- (NSString *)getName;

- (id<OrgSpongycastleUtilTestTestResult>)perform;

- (void)performTest;

#pragma mark Protected

- (jboolean)areEqualWithByteArray:(IOSByteArray *)a
                    withByteArray:(IOSByteArray *)b;

- (jboolean)areEqualWithByteArray2:(IOSObjectArray *)left
                    withByteArray2:(IOSObjectArray *)right;

- (void)failWithNSString:(NSString *)message;

- (void)failWithNSString:(NSString *)message
                  withId:(id)expected
                  withId:(id)found;

- (void)failWithNSString:(NSString *)message
   withJavaLangThrowable:(JavaLangThrowable *)throwable;

- (void)isEqualsWithInt:(jint)a
                withInt:(jint)b;

- (void)isEqualsWithLong:(jlong)a
                withLong:(jlong)b;

- (void)isEqualsWithId:(id)a
                withId:(id)b;

- (void)isEqualsWithNSString:(NSString *)message
                 withBoolean:(jboolean)a
                 withBoolean:(jboolean)b;

- (void)isEqualsWithNSString:(NSString *)message
                    withLong:(jlong)a
                    withLong:(jlong)b;

- (void)isEqualsWithNSString:(NSString *)message
                      withId:(id)a
                      withId:(id)b;

- (void)isTrueWithBoolean:(jboolean)value;

- (void)isTrueWithNSString:(NSString *)message
               withBoolean:(jboolean)value;

+ (void)runTestWithOrgSpongycastleUtilTestTest:(id<OrgSpongycastleUtilTestTest>)test;

+ (void)runTestWithOrgSpongycastleUtilTestTest:(id<OrgSpongycastleUtilTestTest>)test
                         withJavaIoPrintStream:(JavaIoPrintStream *)outArg;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleUtilTestSimpleTest)

FOUNDATION_EXPORT void OrgSpongycastleUtilTestSimpleTest_init(OrgSpongycastleUtilTestSimpleTest *self);

FOUNDATION_EXPORT void OrgSpongycastleUtilTestSimpleTest_runTestWithOrgSpongycastleUtilTestTest_(id<OrgSpongycastleUtilTestTest> test);

FOUNDATION_EXPORT void OrgSpongycastleUtilTestSimpleTest_runTestWithOrgSpongycastleUtilTestTest_withJavaIoPrintStream_(id<OrgSpongycastleUtilTestTest> test, JavaIoPrintStream *outArg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilTestSimpleTest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilTestSimpleTest")
