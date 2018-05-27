#!/usr/bin/env python
"""Parses the postscreen logs and display stats."""
# mjc - 20180514

from __future__ import print_function
from collections import defaultdict
from datetime import datetime as dt
from decimal import Decimal, getcontext
from getopt import getopt
from re import escape, match, search, split
from sys import argv
from time import mktime, strptime


def usage():
    """Prints the usage of the program."""
    print("""
postscreen_stats.py
    parses Postfix logs to compute statistics on postscreen activity

usage: postscreen_stats.py -f maillog

  -a|--action=   action filter with operators | and &
    ex. 'PREGREET&DNSBL|HANGUP' = ((PREGREET and DNSBL) or HANGUP)
    ex. 'HANGUP&DNSBL|PREGREET&DNSBL'
      = ((HANGUP and DNSBL) or (PREGREET and DNSBL)

  -f|--file=    log file to parse (default is /var/log/maillog)

  --geofile=    path to a GeoLiteCity.dat MaxMind GeoLite City database file
                Download "GeoLite City" Binary for free from MaxMind at:
                http://dev.maxmind.com/geoip/legacy/geolite/

  -i|--ip=      filters the results on a specific IP

  --mapdest=    path to a destination HTML file to display maps result
                *** Require geolocation with --geofile option ***

  --map-min-conn=   When creating a map, only show IPs which connected X times

  --report=     report mode {short|full|ip|none} (default is short)

  -y|--year=    select the year of the logs (default is current year)

  --rfc3339     set the timestamp format to "2012-04-13T08:53:00+02:00"
                instead of the regular syslog format "Oct 23 04:02:17"

example command:
$ postscreen_stats.py -f maillog --geofile=GeoLiteCity.dat --mapdest=report.html

Julien Vehent https://jve.linuxwall.info/
https://github.com/jvehent/Postscreen-Stats
""")


def gen_unix_ts(syslog_ts):
    """Convert the syslog time stamp into unix format and return it."""
    full_ts = 0
    unix_ts = 0
    now_ts = dt.now()
    unix_ts = int(now_ts)
    if RFC3339:
        date = syslog_ts.split('+', 1)
        # example format: 2012-04-13T08:53:00+02:00
        full_ts = strptime(date[0], '%Y-%m-%dT%H:%M:%S')
        unix_ts = mktime(full_ts)
    else:
        # add the year
        syslog_ts = str(YEAR) + " " + syslog_ts
        # example format: 2011 Oct 23 04:02:17
        full_ts = strptime(syslog_ts, '%Y %b %d %H:%M:%S')
        unix_ts = mktime(full_ts)

    # check if the unix_ts is in the future then bail
    if unix_ts > mktime(now_ts.timetuple()):
        print("ERROR: Calculated date from syslog time stamp is in the future!?")
        print("Are you really parsing mail logs from year " + str(YEAR) + " ?")
        exit()
    else:
        return unix_ts


class ClientStat(object):  # pylint: disable=too-few-public-methods
    """Each client's statistics are stored in the class"""
    def __init__(self):
        self.logs = defaultdict(int)     # connection logs
        self.actions = defaultdict(int)  # postscreen action logs
        self.dnsbl_ranks = []            # list of ranks triggered when blocked
        self.geoloc = defaultdict(int)

    def action_filter(self, ac_filter):
        """Return true if the object matches the ACTION_FILTER"""
        _pass_action_filter = 0
        _and_action_filter = 0
        # if the ACTION_FILTER is defined, iterate through the action
        # and process only the clients with a matching action
        if ac_filter is None:
            _pass_action_filter = 1
        else:
            for or_action in ac_filter.split("|"):
                if _pass_action_filter == 0:
                    _and_action_filter = 0
                    for and_action in or_action.split("&"):
                        if self.actions[and_action] > 0 and _and_action_filter >= 0:
                            _and_action_filter = 1
                        else:
                            _and_action_filter = -1
                    if _and_action_filter > 0:
                        _pass_action_filter = 1
        if _pass_action_filter == 1:
            return True
        return False

# VARIABLES
IP_REGEXP = r"((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}" \
            "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
IP_FILTER = " "
ACTION_FILTER = None
NOW = dt.now()
YEAR = NOW.year
REPORT_MODE = "short"
LOG_FILE = "/var/log/maillog"
GEOFILE = ""
MAPDEST = ""
RFC3339 = False
MAP_MIN_CONN = 0

# position of 'postscreen' inside the logs
LOG_CURSOR = 5

# the list of clients ips and pointer to instance of class
IP_LIST = {}

# command line arguments
ARGS_LIST, REMAINDER = getopt(argv[1:], 'a:i:f:y:h', [
    'action=', 'geofile=', 'mapdest=', 'ip=', 'year=', 'report=',
    'help', 'file=', 'rfc3339', 'map-min-conn='])

for argument, value in ARGS_LIST:
    if argument in ('-a', '--action'):
        ACTION_FILTER = str(value)
    elif argument in '--geofile':
        GEOFILE = value
    elif argument in ('-f', '--file'):
        LOG_FILE = value
    elif argument in ('-y', '--year'):
        YEAR = value
    elif argument in '--rfc3339':
        RFC3339 = True
        LOG_CURSOR = 3
    elif argument in ('-i', '--ip'):
        IP_FILTER = value
        print("Filtering results on IP", IP_FILTER)
    elif argument in '--report':
        if value in ('short', 'full', 'ip', 'none'):
            REPORT_MODE = value
        else:
            print("ERROR: Unknown report type")
            usage()
            exit()
    elif argument in '--mapdest':
        MAPDEST = value
        print("HTML map file will be generated at ", MAPDEST)
    elif argument in '--map-min-conn':
        MAP_MIN_CONN = int(value)
    elif argument in ('-h', '--help'):
        usage()
        exit()

# Geo location file is in use
if GEOFILE not in "":
    from imp import find_module
    try:
        find_module("pygeoip")
        print("Using pygeoip module to open Geolocation ")
        import pygeoip
        GI = pygeoip.GeoIP(GEOFILE, pygeoip.MEMORY_CACHE)
    except ImportError:
        try:
            find_module("GeoIP")
            print("Using GeoIP module to open Geolocation ")
            import GeoIP
            GI = GeoIP.open(GEOFILE, GeoIP.GEOIP_MEMORY_CACHE)
        except ImportError:
            print("ERROR: Could not import pygeoip or GeoIP modules for Geolocation!")
            print("Install one/both modules or re-run without --geofile option.")
            exit()
    print("MaxMind GeoLite City database file ", GEOFILE)

try:
    MAILLOG = open(LOG_FILE)
except IOError as ioe:
    print("Cannot open maillog! ", ioe)
    exit(1)
else:
    for line in MAILLOG:
        # Get postscreen logs only
        if "/postscreen[" in line:
            # apply the user defined IP filter
            if IP_FILTER in line:
                # parse the log line
                line_fields = line.split(None, LOG_CURSOR + 1)

                # parse the ip
                current_ip = '999.999.999.999'
                if search(IP_REGEXP, line_fields[LOG_CURSOR + 1]):
                    t = split(IP_REGEXP, line_fields[LOG_CURSOR + 1], maxsplit=1)
                    current_ip = t[1]
                    del t

                if match("^CONNECT$", line_fields[LOG_CURSOR]):
                    if RFC3339:
                        syslog_date = line_fields[0]
                    else:
                        syslog_date = line_fields[0] + " " + line_fields[1] + \
                            " " + line_fields[2]

                    # first time we see the client, initiate a class instance
                    # store in in the client_list dictionary
                    if current_ip not in IP_LIST:
                        IP_LIST[current_ip] = ClientStat()
                        IP_LIST[current_ip].logs["FIRST SEEN"] = \
                            gen_unix_ts(syslog_date)
                        IP_LIST[current_ip].logs["LAST SEEN"] = \
                            gen_unix_ts(syslog_date)
                        # perform Geolocation
                        if GEOFILE not in "":
                            IP_LIST[current_ip].geoloc = GI.record_by_addr(current_ip)

                    # ip is already known, update the last_seen timestamp
                    else:
                        IP_LIST[current_ip].logs["LAST SEEN"] = \
                            gen_unix_ts(syslog_date)

                    IP_LIST[current_ip].logs["CONNECT"] += 1

                # client must be initialized to continue
                # the string matching is organized to test the most probable
                # value first, to speed things up
                elif current_ip in IP_LIST:
                    if match("^PASS$", line_fields[LOG_CURSOR]):
                        if search("^OLD", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["PASS OLD"] += 1

                            # if the connection count is 2, and the IP has already
                            # been rejected with a code 450 calculate the
                            # reconnection delay
                            if (IP_LIST[current_ip].logs["CONNECT"] == 2 and
                                    IP_LIST[current_ip].actions["NOQUEUE 450 deep protocol test reconnection"] > 0):
                                IP_LIST[current_ip].logs["RECO. DELAY (graylist)"] = \
                                    IP_LIST[current_ip].logs["LAST SEEN"] - \
                                    IP_LIST[current_ip].logs["FIRST SEEN"]

                        elif search("^NEW", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["PASS NEW"] += 1

                    elif match("^NOQUEUE:$", line_fields[LOG_CURSOR]):
                        if search("too many connections", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["NOQUEUE too many connections"] += 1
                        elif search("all server ports busy", line_fields[LOG_CURSOR]):
                            IP_LIST[current_ip].actions["NOQUEUE all server ports busy"] += 1
                        elif search("450 4.3.2 Service currently unavailable", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["NOQUEUE 450 deep protocol test reconnection"] += 1

                    elif match("^HANGUP$", line_fields[LOG_CURSOR]):
                        IP_LIST[current_ip].actions["HANGUP"] += 1

                    elif match("^DNSBL$", line_fields[LOG_CURSOR]):
                        IP_LIST[current_ip].actions["DNSBL"] += 1
                        # store the rank
                        rank_line = line_fields[LOG_CURSOR + 1].split(None)
                        IP_LIST[current_ip].dnsbl_ranks.append(rank_line[1])

                    elif match("^PREGREET$", line_fields[LOG_CURSOR]):
                        IP_LIST[current_ip].actions["PREGREET"] += 1

                    elif match("^COMMAND$", line_fields[LOG_CURSOR]):
                        if search("^PIPELINING", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["COMMAND PIPELINING"] += 1

                        elif search("^TIME LIMIT", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["COMMAND TIME LIMIT"] += 1

                        elif search("^COUNT LIMIT", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["COMMAND COUNT LIMIT"] += 1

                        elif search("^LENGTH LIMIT", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["COMMAND LENGTH LIMIT"] += 1

                    elif match("^WHITELISTED$", line_fields[LOG_CURSOR]):
                        IP_LIST[current_ip].actions["WHITELISTED"] += 1

                    elif match("^BLACKLISTED$", line_fields[LOG_CURSOR]):
                        IP_LIST[current_ip].actions["BLACKLISTED"] += 1

                    elif match("^BARE$", line_fields[LOG_CURSOR]):
                        if search("^NEWLINE", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["BARE NEWLINE"] += 1

                    elif match("^NON-SMTP$", line_fields[LOG_CURSOR]):
                        if search("^COMMAND", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["NON-SMTP COMMAND"] += 1

                    elif match("^WHITELIST$", line_fields[LOG_CURSOR]):
                        if search("^VETO", line_fields[LOG_CURSOR + 1]):
                            IP_LIST[current_ip].actions["WHITELIST VETO"] += 1

    # done with the log file
    MAILLOG.close()


# additional reports shown in full mode only
if REPORT_MODE in ('full', 'ip'):
    for client in IP_LIST:
        print(client)
        for log in sorted(IP_LIST[client].logs):
            if log in ('FIRST SEEN', 'LAST SEEN'):
                print("\t", log, ":", dt.fromtimestamp(int(
                    IP_LIST[client].logs[log])).strftime('%Y-%m-%d %H:%M:%S'))
            else:
                print("\t", log, ":", IP_LIST[client].logs[log])
        print("\t--- postscreen actions ---")
        for action in sorted(IP_LIST[client].actions):
            print("\t", action, ":", IP_LIST[client].actions[action])
            if action in 'DNSBL':
                print("\tDNSBL ranks:", IP_LIST[client].dnsbl_ranks)
        if GEOFILE not in "":
            print("\tGeoLoc:", IP_LIST[client].geoloc)
        print("")


# store the list of blocked clients for map generation
if MAPDEST not in "" and GEOFILE not in "":
    BLOCKED_CLIENTS = defaultdict(int)

POSTSCREEN_STATS = defaultdict(int)
CLIENTS = defaultdict(int)
COMEBACK = {'<10s': 0, '10s to 30s': 0, '>30s to 1min': 0, '>1min to 5min': 0,
            '>5 min to 30min': 0, '>30min to 2h': 0, '>2h to 5h': 0,
            '>5h to 12h': 0, '>12h to 24h': 0, '>24h': 0}
BLOCKED_COUNTRIES = defaultdict(int)


# normal report mode
if REPORT_MODE in ('short', 'full', 'none'):
    # basic accounting, browse through the list of objects and count
    # the occurences
    for client in IP_LIST:
        # go to the next client if this one doesn't match the action filter
        if not IP_LIST[client].action_filter(ACTION_FILTER):
            continue

        CLIENTS["clients"] += 1
        # calculate the average reconnection delay (graylist)
        if IP_LIST[client].logs["RECO. DELAY (graylist)"] > 0:
            CLIENTS["reconnections"] += 1
            CLIENTS["seconds avg. reco. delay"] += \
                IP_LIST[client].logs["RECO. DELAY (graylist)"]
            if IP_LIST[client].logs["RECO. DELAY (graylist)"] < 10:
                COMEBACK['<10s'] += 1
            elif 10 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 30:
                COMEBACK['10s to 30s'] += 1
            elif 30 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 60:
                COMEBACK['>30s to 1min'] += 1
            elif 60 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 300:
                COMEBACK['>1min to 5min'] += 1
            elif 300 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 1800:
                COMEBACK['>5 min to 30min'] += 1
            elif 1800 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 7200:
                COMEBACK['>30min to 2h'] += 1
            elif 7200 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 18000:
                COMEBACK['>2h to 5h'] += 1
            elif 18000 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 43200:
                COMEBACK['>5h to 12h'] += 1
            elif 43200 < IP_LIST[client].logs["RECO. DELAY (graylist)"] <= 86400:
                COMEBACK['>12h to 24h'] += 1
            else:
                COMEBACK['>24h'] += 1

        for action in sorted(IP_LIST[client].actions):
            POSTSCREEN_STATS[action] += IP_LIST[client].actions[action]

        # calculate the average DNSBL trigger level
        if IP_LIST[client].actions["DNSBL"] > 0:
            for rank in IP_LIST[client].dnsbl_ranks:
                CLIENTS["avg. dnsbl rank"] += int(rank)

        # if client was blocked at any point, add its country to the count
        if (GEOFILE not in "" and  # pylint: disable=too-many-boolean-expressions
                IP_LIST[client].geoloc > 0 and (
                    IP_LIST[client].actions["BLACKLISTED"] > 0 or
                    IP_LIST[client].actions["DNSBL"] > 0 or
                    IP_LIST[client].actions["PREGREET"] > 0 or
                    IP_LIST[client].actions["COMMAND PIPELINING"] > 0 or
                    IP_LIST[client].actions["COMMAND TIME LIMIT"] > 0 or
                    IP_LIST[client].actions["COMMAND COUNT LIMIT"] > 0 or
                    IP_LIST[client].actions["COMMAND LENGTH LIMIT"] > 0 or
                    IP_LIST[client].actions["BARE NEWLINE"] > 0 or
                    IP_LIST[client].actions["NON-SMTP COMMAND"] > 0)):
            BLOCKED_COUNTRIES[IP_LIST[client].geoloc["country_name"]] += 1
            CLIENTS["blocked clients"] += 1
            if MAPDEST not in "":
                BLOCKED_CLIENTS[client] = 1

    # calculate the average reconnection delay
    if CLIENTS["reconnections"] > 0:
        CLIENTS["seconds avg. reco. delay"] /= CLIENTS["reconnections"]

    # calculate the average DNSBL trigger rank
    if POSTSCREEN_STATS["DNSBL"] > 0 and CLIENTS["avg. dnsbl rank"] > 0:
        CLIENTS["avg. dnsbl rank"] /= POSTSCREEN_STATS["dnsbl"]

if REPORT_MODE in ('short', 'full'):
    # display unique clients and total postscreen actions
    print("\n=== unique clients/total postscreen actions ===")
    # print the count of CONNECT first (apply the ACTION_FILTER)
    print(str(len([cs.logs['CONNECT'] for cs in IP_LIST.items()
                   if cs.logs['CONNECT'] > 0 and cs.action_filter(ACTION_FILTER)]))
          + "/" + str(sum([cs.logs['CONNECT'] for cs in IP_LIST.items()
                           if cs.logs['CONNECT'] > 0 and cs.action_filter(ACTION_FILTER)]))
          + " CONNECT")
    # then print the list of actions, ACTION_FILTER was applied earlied
    # when the POSTSCREEN_STATS dictionary was built
    for action in sorted(POSTSCREEN_STATS):
        print(str(len([cs.actions[action] for cs in IP_LIST.items()
                       if cs.actions[action] > 0 and cs.action_filter(ACTION_FILTER)]))
              + "/" + str(POSTSCREEN_STATS[action]), action)

    print("\n=== clients statistics ===")
    for stat in sorted(CLIENTS):
        print(CLIENTS[stat], stat)

    if CLIENTS["reconnections"] > 0:
        print("\n=== First reconnection delay (graylist) ===")
        print("delay | <10s | 10to30s | >30to1m | >1to5m | >5to30m | " +
              ">30mto2h | >2hto5h | >5hto12h | >12to24h | >24h |")
        # display the absolute values
        print("count | ")
        print(str(COMEBACK['<10s']).ljust(5) + "| ")
        print(str(COMEBACK['10s to 30s']).ljust(8) + "| ")
        print(str(COMEBACK['>30s to 1min']).ljust(8) + "| ")
        print(str(COMEBACK['>1min to 5min']).ljust(7) + "| ")
        print(str(COMEBACK['>5 min to 30min']).ljust(8) + "| ")
        print(str(COMEBACK['>30min to 2h']).ljust(9) + "| ")
        print(str(COMEBACK['>2h to 5h']).ljust(8) + "| ")
        print(str(COMEBACK['>5h to 12h']).ljust(9) + "| ")
        print(str(COMEBACK['>12h to 24h']).ljust(9) + "| ")
        print(str(COMEBACK['>24h']).ljust(5) + "|")
        # calculate and display the percentages
        getcontext().prec = 2
        DEC_CAMEBACK = Decimal(CLIENTS["reconnections"])

        print("pct % | ")
        print(str(Decimal(COMEBACK['<10s']) /
                  DEC_CAMEBACK * 100).ljust(5) + "| ")
        print(str(Decimal(COMEBACK['10s to 30s']) /
                  DEC_CAMEBACK * 100).ljust(8) + "| ")
        print(str(Decimal(COMEBACK['>30s to 1min']) /
                  DEC_CAMEBACK * 100).ljust(8) + "| ")
        print(str(Decimal(COMEBACK['>1min to 5min']) /
                  DEC_CAMEBACK * 100).ljust(7) + "| ")
        print(str(Decimal(COMEBACK['>5 min to 30min']) /
                  DEC_CAMEBACK * 100).ljust(8) + "| ")
        print(str(Decimal(COMEBACK['>30min to 2h']) /
                  DEC_CAMEBACK * 100).ljust(9) + "| ")
        print(str(Decimal(COMEBACK['>2h to 5h']) /
                  DEC_CAMEBACK * 100).ljust(8) + "| ")
        print(str(Decimal(COMEBACK['>5h to 12h']) /
                  DEC_CAMEBACK * 100).ljust(9) + "| ")
        print(str(Decimal(COMEBACK['>12h to 24h']) /
                  DEC_CAMEBACK * 100).ljust(9) + "| ")
        print(str(Decimal(COMEBACK['>24h']) /
                  DEC_CAMEBACK * 100).ljust(5) + "|")

    if GEOFILE not in "":
        TOTAL_BLOCKED = Decimal(CLIENTS["blocked clients"])
        print("\n=== Top 20 Countries of Blocked Clients ===")
        from operator import itemgetter
        SORTED_COUNTRIES = BLOCKED_COUNTRIES.items()
        SORTED_COUNTRIES.sort(key=itemgetter(1), reverse=True)
        COUNT_FORMAT = ""
        for i in range(20):
            if i < len(SORTED_COUNTRIES):
                country, CLIENTS = SORTED_COUNTRIES[i]
                if COUNT_FORMAT in "":
                    COUNT_FORMAT = "%" + str(len(str(CLIENTS))) + "d"
                client_percent = "(%5.2f%%)" % \
                    float(Decimal(CLIENTS) / TOTAL_BLOCKED * 100)
                print(COUNT_FORMAT % CLIENTS, client_percent, country)

# generate the HTML for the map and store it in a file
if MAPDEST not in "" and GEOFILE not in "":
    FD = open(MAPDEST, "w")
    MAPCODE = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "https://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="https://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
        <title>Postscreen GeoMap of Blocked IPs</title>
        <script type="text/javascript"
            src="https://maps.google.com/maps/api/js?sensor=false"></script>
        <script type="text/javascript">
        var ip = new Array();
        var marker_ip = new Array();
        var desc_ip = new Array();
        var info_window = new Array();

            window.onload = function() {
                var center = new google.maps.LatLng(0,0);
                var mapOptions = {
                    zoom: 2,
                    center: center,
                    mapTypeId: google.maps.MapTypeId.TERRAIN
                };
                var myMap = new google.maps.Map(
                    document.getElementById('map'),mapOptions
                );
'''
    FD.write(MAPCODE)

    INCR = 0
    for client in BLOCKED_CLIENTS:
        if not IP_LIST[client].geoloc is None \
           and 'latitude' in IP_LIST[client].geoloc \
           and 'longitude' in IP_LIST[client].geoloc:

            MAPCODE = '''
            ip[''' + str(INCR) + '''] = new google.maps.LatLng(''' \
                   + str(IP_LIST[client].geoloc['latitude']) + "," \
                   + str(IP_LIST[client].geoloc['longitude']) + ''');
            marker_ip[''' + str(INCR) + '''] = new google.maps.Marker({
                      position: ip[''' + str(INCR) + '''], map: myMap,
                      title: "''' + str(client) + '''"});
            desc_ip[''' + str(INCR) + '''] = '<div id="content">' +
                    '<div id="siteNotice"></div>' +
                    '<h2 id="firstHeading" class="firstHeading">' +
                    ' ''' + str(client) + '''</h2><div id="bodyContent">' +
                    ' '''
            FD.write(MAPCODE)

            for log in sorted(IP_LIST[client].logs):
                if log in ('FIRST SEEN', 'LAST SEEN'):
                    MAPCODE = '<p>' + log + ": " + str(dt.fromtimestamp(int(
                        IP_LIST[client].logs[log])).strftime('%Y-%m-%d %H:%M:%S')) \
                        + '''</p>' + ' '''
                    FD.write(MAPCODE)
                else:
                    MAPCODE = '<p>' + log + ": " + str(IP_LIST[client].logs[log]) + \
                        '''</p>' + ' '''
                    FD.write(MAPCODE)

            for action in sorted(IP_LIST[client].actions):
                if IP_LIST[client].actions[action] > 0:
                    MAPCODE = '<p>' + action + ": " + \
                              str(IP_LIST[client].actions[action]) + \
                              '''</p>' + ' '''
                    FD.write(MAPCODE)

        if action in 'DNSBL':
            MAPCODE = '<p>' + "DNSBL ranks: "
            FD.write(MAPCODE)
            for rank in IP_LIST[client].dnsbl_ranks:
                MAPCODE = " " + str(rank) + ","
                FD.write(MAPCODE)
                MAPCODE = '''</p>' + ' '''
                FD.write(MAPCODE)

            if 'city' in IP_LIST[client].geoloc:
                MAPCODE = '<p>' + 'Location: ' + \
                    escape(str(IP_LIST[client].geoloc['city'])) + ", " + \
                    escape(str(IP_LIST[client].geoloc['country_code'])) + \
                    '''<p> ' + ' '''
                FD.write(MAPCODE)

                MAPCODE = '''</div></div>';
  info_window[''' + str(INCR) + '''] = new google.maps.InfoWindow({
  content: desc_ip[''' + str(INCR) + '''], maxWidth: 500});
  google.maps.event.addListener(marker_ip[''' + str(INCR) + '''], 'click',
  function() {
    info_window[''' + str(INCR) + '''].open(myMap,
    marker_ip[''' + str(INCR) + ''']);
             });
'''
            INCR += 1
        FD.write(MAPCODE)

    MAPCODE = '''
    }
    </script>
    <style type="text/css">
        #map {
            width:100%;
            height:800px;
        }
    </style>
  </head>
  <body>
    <h1>Postscreen Map of Blocked IPs</h1>
    <div id="map"></div>
    <p>mapping ''' + str(len(BLOCKED_CLIENTS)) + ''' blocked IPs</p>
    <p>generated using
    <a href="https://github.com/jvehent/Postscreen-Stats">Postscreen-Stats</a>
    by <a href="https://jve.linuxwall.info/">Julien Vehent</a></p>
  </body>
</html>
'''
    FD.write(MAPCODE)
    FD.close()
    print("Created HTML map file at ", MAPDEST)
