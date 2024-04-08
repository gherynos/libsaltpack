# - Find MsgPack includes and library
#
# This module defines
#  MSGPACK_INCLUDE_DIR
#  MSGPACK_FOUND, If false, do not try to use MSGPACK
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

IF (MSGPACK_INCLUDE_DIR)
  SET(MSGPACK_FIND_QUIETLY TRUE) # Already in cache, be silent
ENDIF (MSGPACK_INCLUDE_DIR)

FIND_PATH(MSGPACK_INCLUDE_DIR msgpack.hpp
        /usr/include
        /usr/include/msgpack
        /usr/local/include
        /usr/local/include/msgpack
)

# Copy the results to the output variables.
IF (MSGPACK_INCLUDE_DIR)
  SET(MSGPACK_FOUND 1)
  SET(MSGPACK_INCLUDE_DIRS ${MSGPACK_INCLUDE_DIR})

  MESSAGE(STATUS "Found msgpack: ${MSGPACK_INCLUDE_DIR}")

ELSE (MSGPACK_INCLUDE_DIR)
  SET(MSGPACK_FOUND 0)
  SET(MSGPACK_INCLUDE_DIRS)
ENDIF (MSGPACK_INCLUDE_DIR)

# Report the results.
IF (NOT MSGPACK_FOUND)
  SET(MSGPACK_DIR_MESSAGE "MsgPack was not found. Make sure MSGPACK_INCLUDE_DIR are set.")
  IF (NOT MSGPACK_FIND_QUIETLY)
    MESSAGE(STATUS "${MSGPACK_DIR_MESSAGE}")
  ELSE (NOT MSGPACK_FIND_QUIETLY)
    IF (MSGPACK_FIND_REQUIRED)
      MESSAGE(FATAL_ERROR "${MSGPACK_DIR_MESSAGE}")
    ENDIF (MSGPACK_FIND_REQUIRED)
  ENDIF (NOT MSGPACK_FIND_QUIETLY)
ENDIF (NOT MSGPACK_FOUND)


MARK_AS_ADVANCED(
        MSGPACK_INCLUDE_DIRS
)