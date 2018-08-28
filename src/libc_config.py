########################
## LibC Function list ##
########################

# TODO: should be updated
skip_function_names         = ['__stack_chk_fail', 'pow']
libc_function_names         = ['memcpy', 'memset', 'memcmp', 'strtod', 'strlen', 'malloc', 'free', 'strcmp', 'strncmp']
libc_comp_function_names    = ['strtod', '_setjmp', 'longjmp', 'gmtime', 'abort', 'fwrite', 'write', 'fread', 'read', 'fopen', 'open', 'fclose', 'close']
