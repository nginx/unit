
#ifndef _NXT_CALENDAR_H_INCLUDED_
#define _NXT_CALENDAR_H_INCLUDED_


typedef struct {
    const char  wday[7][4];
    const char  month[12][4];
} nxt_calendar_t;


extern const nxt_calendar_t  nxt_calendar;


#endif  /* _NXT_HTTP_H_INCLUDED_ */
