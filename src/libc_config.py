########################
## LibC Function list ##
########################

# TODO: should be updated
skip_function_names         = ['__stack_chk_fail', '@__security_check_cookie@4', '__assert_fail', 'pow', '__allmul', '__aulldiv', '__alloca_probe']
libc_function_names         = ['memcpy', 'memset', 'memcmp', 'strtod', 'strlen', 'malloc', 'free', 'strcmp', 'strncmp']
libc_comp_function_names    = ['strtod', '_setjmp', 'longjmp', 'gmtime', 'abort', 'fwrite', 'write', 'fread', 'read', 'fopen', 'open', 'fclose', 'close']
