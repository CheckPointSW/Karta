########################
## LibC Function list ##
########################

# TODO: should be updated
libc_function_names         = ['memcpy', 'memset', 'memcmp', 'strtod', 'strlen', 'malloc', 'free', 'strcmp', 'strncmp', 'strchr']
libc_comp_function_names    = ['strtod', '_setjmp', 'longjmp', 'gmtime', 'abort', 'fwrite', 'write', 'fread', 'read', 'fopen', 'open', 'fclose', 'close', 'fputc', 'fgetc', 'fgets', 'fputs', 'qsort']
libc_functions              = libc_function_names + libc_comp_function_names

gcc_skip_math_functions     = ['pow', 'exp', 'sqrt', 'floor']
gcc_skip_functions          = gcc_skip_math_functions + ['__stack_chk_fail']

windows_skip_math_functions = ['_allmul', '_aulldiv']
windows_skip_functions      = windows_skip_math_functions + ['___security_cookie', '@__security_check_cookie@4', '_assert_fail', '_alloca_probe', '__report_rangecheckfailure', '_imp___wassert']

skip_function_names         = gcc_skip_functions + windows_skip_functions
