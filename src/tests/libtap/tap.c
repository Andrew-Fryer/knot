#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "tap.h"

static int expected_tests = NO_PLAN;
static int failed_tests;
static int current_test;
static char *todo_mesg;

void
plan (int tests) {
    expected_tests = tests;
    if (tests != NO_PLAN)
        printf("1..%d\n", tests);
}

static char *
vstrdupf (const char *fmt, va_list args) {
    char *str;
    int size = vsnprintf(NULL, 0, fmt, args) + 1;
    str = malloc(size);
    vsprintf(str, fmt, args);
    return str;
}

int
vok_at_loc (const char *file, int line, int test, const char *fmt,
            va_list args)
{
    char *name = vstrdupf(fmt, args);
    printf("%sok %d", test ? "" : "not ", ++current_test);
    if (*name)
        printf(" - %s", name);
    if (todo_mesg) {
        printf(" # TODO");
        if (*todo_mesg)
            printf(" %s", todo_mesg);
    }
    printf("\n");
    if (!test) {
        if (*name)
            diag("  Failed%s test '%s'\n  at %s line %d.",
                todo_mesg ? " (TODO)" : "", name, file, line);
        else
            diag("  Failed%s test at %s line %d.",
                todo_mesg ? " (TODO)" : "", file, line);

        if (!todo_mesg)
            failed_tests++;
    }
    free(name);
    return test;
}

int
ok_at_loc (const char *file, int line, int test, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vok_at_loc(file, line, test, fmt, args);
    va_end(args);
    return test;
}

static int
mystrcmp (const char *a, const char *b) {
    return a == b ? 0 : !a ? -1 : !b ? 1 : strcmp(a, b);
}

#define eq(a, b) (!mystrcmp(a, b))
#define ne(a, b) (mystrcmp(a, b))

int
is_at_loc (const char *file, int line, const char *got, const char *expected,
           const char *fmt, ...)
{
    int test = eq(got, expected);
    va_list args;
    va_start(args, fmt);
    vok_at_loc(file, line, test, fmt, args);
    va_end(args);
    if (!test) {
        diag("         got: '%s'", got);
        diag("    expected: '%s'", expected);
    }
    return test;
}

int
isnt_at_loc (const char *file, int line, const char *got, const char *expected,
             const char *fmt, ...)
{
    int test = ne(got, expected);
    va_list args;
    va_start(args, fmt);
    vok_at_loc(file, line, test, fmt, args);
    va_end(args);
    if (!test) {
        diag("         got: '%s'", got);
        diag("    expected: anything else");
    }
    return test;
}

int
cmp_ok_at_loc (const char *file, int line, int a, const char *op, int b,
               const char *fmt, ...)
{
    int test = eq(op, "||") ? a || b
             : eq(op, "&&") ? a && b
             : eq(op, "|")  ? a |  b
             : eq(op, "^")  ? a ^  b
             : eq(op, "&")  ? a &  b
             : eq(op, "==") ? a == b
             : eq(op, "!=") ? a != b
             : eq(op, "<")  ? a <  b
             : eq(op, ">")  ? a >  b
             : eq(op, "<=") ? a <= b
             : eq(op, ">=") ? a >= b
             : eq(op, "<<") ? a << b
             : eq(op, ">>") ? a >> b
             : eq(op, "+")  ? a +  b
             : eq(op, "-")  ? a -  b
             : eq(op, "*")  ? a *  b
             : eq(op, "/")  ? a /  b
             : eq(op, "%")  ? a %  b
             : diag("unrecognized operator '%s'", op);
    va_list args;
    va_start(args, fmt);
    vok_at_loc(file, line, test, fmt, args);
    va_end(args);
    if (!test) {
        diag("    %d", a);
        diag("        %s", op);
        diag("    %d", b);
    }
    return test;
}

int
diag (const char *fmt, ...) {

   va_list args;
   va_start(args, fmt);
   int len = vsnprintf(NULL, 0, fmt, args);
   va_end(args);

   if(len <= 0) {
      return -1;
   }

   char* buf = malloc(len + 1);

   va_start(args, fmt);
   len = vsprintf(buf, fmt, args);
   va_end(args);

   char* begin = buf;
   char* end = strchr(begin, '\n');
   for(;;) {
      fprintf(stderr, "# ");
      if(end == NULL) {
         end = buf + len;
         write(fileno(stderr), begin, end - begin + 1);
         break;
      }

      write(fileno(stderr), begin, end - begin + 1);
      begin = end + 1;
      if(*begin == '\0') {
         break;
      }

      end = strchr(begin + 1, '\n');
   }

   free(buf);

   fprintf(stderr,"\n");
   return 0;
}

int
note (const char *fmt, ...) {

   va_list args;
   va_start(args, fmt);
   int len = vsnprintf(NULL, 0, fmt, args);
   va_end(args);

   if(len <= 0) {
      return -1;
   }

   char* buf = malloc(len + 1);

   va_start(args, fmt);
   len = vsprintf(buf, fmt, args);
   va_end(args);

   char* begin = buf;
   char* end = strchr(begin, '\n');
   for(;;) {
      fprintf(stderr, "# ");
      if(end == NULL) {
         end = buf + len;
         write(fileno(stdout), begin, end - begin + 1);
         break;
      }

      write(fileno(stdout), begin, end - begin + 1);
      begin = end + 1;
      if(*begin == '\0') {
         break;
      }

      end = strchr(begin + 1, '\n');
   }

   free(buf);

   fprintf(stdout,"\n");
   return 0;
}

int
exit_status () {
    int retval = 0;
    if (expected_tests == NO_PLAN) {
        printf("1..%d\n", current_test);
    }
    else if (current_test != expected_tests) {
        diag("Looks like you planned %d test%s but ran %d.",
            expected_tests, expected_tests > 1 ? "s" : "", current_test);
        retval = 255;
    }
    if (failed_tests) {
        diag("Looks like you failed %d test%s of %d run.",
            failed_tests, failed_tests > 1 ? "s" : "", current_test);
        if (expected_tests == NO_PLAN)
            retval = failed_tests;
        else
            retval = expected_tests - current_test + failed_tests;
    }
    return retval;
}

void
skippy (int n, const char *fmt, ...) {
    char *why;
    va_list args;
    va_start(args, fmt);
    why = vstrdupf(fmt, args);
    va_end(args);
    while (n --> 0) {
        printf("ok %d ", ++current_test);
        note("skip %s\n", why);
    }
    free(why);
}

void
ctodo (int ignore, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    todo_mesg = vstrdupf(fmt, args);
    va_end(args);
}

void
cendtodo () {
    free(todo_mesg);
    todo_mesg = NULL;
}

#ifndef _WIN32
#include <sys/mman.h>
#include <regex.h>

/* Create a shared memory int to keep track of whether a piece of code executed
dies. to be used in the dies_ok and lives_ok macros  */
int
tap_test_died (int status) {
    static int *test_died = NULL;
    int prev;
    if (!test_died) {
        test_died = mmap(0, sizeof (int), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        *test_died = 0;
    }
    prev = *test_died;
    *test_died = status;
    return prev;
}

int
like_at_loc (int for_match, const char *file, int line, const char *got,
             const char *expected, const char *fmt, ...)
{
    int test;
    regex_t re;
    int err = regcomp(&re, expected, REG_EXTENDED);
    if (err) {
        char errbuf[256];
        regerror(err, &re, errbuf, sizeof errbuf);
        fprintf(stderr, "Unable to compile regex '%s': %s at %s line %d\n",
                        expected, errbuf, file, line);
        exit(255);
    }
    err = regexec(&re, got, 0, NULL, 0);
    regfree(&re);
    test = for_match ? !err : err;
    va_list args;
    va_start(args, fmt);
    vok_at_loc(file, line, test, fmt, args);
    va_end(args);
    if (!test) {
        if (for_match) {
            diag("                   '%s'", got);
            diag("    doesn't match: '%s'", expected);
        }
        else {
            diag("                   '%s'", got);
            diag("          matches: '%s'", expected);
        }
    }
    return test;
}
#endif

