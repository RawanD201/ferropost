#!/bin/bash
# Nothing to reload before supervisord has started fail2ban (core.sh runs
# this at start-up, before it).
if [[ ${FAIL2BAN_INIT} == "y" ]] && /usr/bin/fail2ban-client ping >/dev/null 2>&1; then
    /usr/bin/fail2ban-client reload core-accesslimit
    /usr/bin/fail2ban-client reload roundcube-accesslimit
fi
