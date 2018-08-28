##################################
## Scoring Configuration values ##
##################################

NUM_BITS_IN_CONST           = 32
MIN_STR_SIZE                = 4
CONST_SPECIAL_VALUES        = [0xFFFFFFFF, -1]
CONST_BOOST_SPECIAL         = 4
CONST_BOOST_BIT_FLAG        = 6
CONST_BOOST_SMALL_FUNCS     = 4
CALL_COUNT_SCORE            = 7
MATCHED_CALL_SCORE          = 3
EXTERNAL_COUNT_SCORE        = 5
STRING_MATCH_SCORE          = 4
STRING_MISMATCH_SCORE       = 4
STRING_NAME_SCORE           = 5
INSTR_COUNT_SCORE           = 0.2
INSTR_COUNT_THRESHOLD       = 5
FUNC_FRAME_SCORE            = 0.2
FRAME_SIZE_THRESHOLD        = 4
FRAME_SAFETY_GAP            = 16
BLOCK_MATCH_SCORE           = 0.1
BLOCK_MISMATCH_SCORE        = 0.1
FUNC_HINT_SCORE             = 20
STATIC_VIOLATION_PENALTY    = 20
LOCATION_BOOST_SCORE        = 15
AGENT_BOOST_SCORE           = 20
EXISTANCE_BOOST_SCORE       = 5
MINIMAL_BLOCKS_BOOST        = 2
ARTEFACT_MATCH_SCORE        = 3
MINIMAL_MATCH_SCORE         = 19.5
SAFTEY_GAP_SCORE            = 10
MINIMAL_ISLAND_SCORE        = 0
MINIMAL_NEIGHBOUR_THRESHOLD = -150
EXT_FUNC_MATCH_SCORE        = 25
LIBC_COMP_FUNC_MATCH_SCORE  = 20
LIBC_FUNC_MATCH_SCORE       = 10
INSTR_RATIO_COUNT_THRESHOLD = 1

#################################
## Anchor Configuration values ##
#################################

MAXIMAL_CONST_SEARCH_TIME   = 60
MAXIMAL_CONST_SEARCH_RATE   = 0.004

STRING_HUGE_LIMIT           = 50
STRING_HUGE_GROUP           = 1
STRING_LONG_LIMIT           = 30
STRING_LONG_GROUP           = 2
STRING_MEDIUM_LIMIT         = 20
STRING_MEDIUM_GROUP         = 3
STRING_SHORT_LIMIT          = 6
STRING_SHORT_GROUP          = 2

CONST_COMPLEX_LIMIT         = 16 # a bit less than 0xdeadbeef
CONST_COMPLEX_GROUP         = 1
CONST_MEDIUM_LIMIT          = 9 # a bit less than 0xdead
CONST_MEDIUM_GROUP          = 2
