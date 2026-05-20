// copyright, zknox, 2025
#ifndef _ZKN_ERRORS_H
#define _ZKN_ERRORS_H

typedef int zkn_error_t;
typedef int zkn_flag_t;

#define ZKN_OK 0
#define ZKN_KO 1


#define ZKN_NOTIMPLEMENTED 0x5A4B4E01
#define ZKN_NOT_INITIALIZED 0x5A4B4E02
#define ZKN_WRONG_LENGTH 0x5A4B4E03
#define ZKN_ERR_INVALID_PARAM 0x5A4B4E04


/* MACROS DEFINITIONS */
#define ZKN_UNUSED(x) (void)(x)

#define ZKN_ERROR_INIT() zkn_error_t error = 0

/* label for the ZKN_CHECK goto */
#define ZKN_ERROR_CLOSE() \
  do                      \
  {                       \
  end: __attribute__((unused)) \
    return error;              \
  } while (0)

/* label for the ZKN_CHECK goto */
#define ZKN_ERROR_CLOSE_SEND()         \
  do                                   \
  {                                    \
  end: __attribute__((unused))         \
    if (error)                  \
      return io_send_sw(error); \
    return 0;                   \
  } while (0)

/* test return function and go to label end if not ok*/
#define ZKN_CHECK(call) \
  do                    \
  {                     \
    error = call;       \
    if (error)          \
    {                   \
      goto end;         \
    }                   \
  } while (0)

#endif