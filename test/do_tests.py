#!/usr/bin/python

from __future__ import print_function

import sys
import subprocess
import re

if "-v" in sys.argv[1:]:
    verbose = True
else:
    verbose = False

def run_test(test_name, test_args, test_status, test_stdout, test_stderr):
    print("{0}: ".format(test_name), end="")
    cmd = ["java", "-jar", "../target/verify_jar.jar"] + test_args
    if verbose:
        print()
        print("  running command:", repr(" ".join(cmd)))
    command = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                                                    stderr = subprocess.PIPE)
    stdout, stderr = command.communicate()
    rc = command.returncode
    if verbose:
        print("  stdout:", repr(stdout))
        print("  stderr:", repr(stderr))
        print("  rc    :", rc)
        print("... ", end="")
    errors = []
    if test_status != rc:
        errors.append(
                "Command returned {0} instead of {1}".format(rc, test_status))
    if not test_stdout[1].match(stdout):
        errors.append(
            "stdout {0!r} does not match /{1}/".format(stdout, test_stdout[0]))
    if not test_stderr[1].match(stderr):
        errors.append(
            "stderr {0!r} does not match /{1}/".format(stderr, test_stderr[0]))
    if errors:
        print("fail")
        for error in errors:
            print ("  " + error, file=sys.stderr)
        result = False
    else:
        print("ok")
        result = True
    if verbose:
        print("--")
    return result

def read_not_comment(file_obj):
    while True:
        line = file_obj.readline()
        if line in (None, ''):
            return None
        if not line.startswith("#"):
            return line.rstrip()

with open("test-cases.txt") as cases_f:
    tests = 0
    passed = 0
    while True:
        test_name = read_not_comment(cases_f)
        if test_name is None:
            break
        if test_name == "--":
            print("Premature test case definition end", file=sys.stderr)
            continue
        test_args = read_not_comment(cases_f)
        if test_args in ("--", None):
            print("Premature test case definition {0!r} end".format(test_name),
                    file=sys.stderr)
            continue
        test_args = test_args.split()
        test_status = read_not_comment(cases_f)
        if test_status in ("--", None):
            print("Premature test case definition {0!r} end".format(test_name),
                    file=sys.stderr)
            continue
        try:
            test_status = int(test_status)
        except ValueError:
            print("Invalid exit status value for test case {0!r}"
                    .format(test_name), file=sys.stderr)
            continue
        test_stdout = read_not_comment(cases_f)
        if test_stdout in ("--", None):
            print("Premature test case definition {0!r} end".format(test_name),
                    file=sys.stderr)
            continue
        try:
            test_stdout = (test_stdout, re.compile(test_stdout, re.DOTALL))
        except re.error:
            print("Invalid stdout regexp in test case {0!r}".format(test_name),
                    file=sys.stderr)
        test_stderr = read_not_comment(cases_f)
        if test_stderr in ("--", None):
            print("Premature test case definition {0!r} end".format(test_name),
                    file=sys.stderr)
            continue
        try:
            test_stderr = (test_stderr, re.compile(test_stderr, re.DOTALL))
        except re.error:
            print("Invalid stderr regexp in test case {0!r}".format(test_name),
                    file=sys.stderr)
        while True:
            line = read_not_comment(cases_f)
            if line in ("--", None):
                break
        tests += 1
        if run_test(test_name, test_args, test_status,
                                                    test_stdout, test_stderr):
            passed += 1
print()
print("{0} of {1} tests passed".format(passed, tests))
if passed < tests:
    print("FAILURE!")
else:
    print("SUCCESS!")

