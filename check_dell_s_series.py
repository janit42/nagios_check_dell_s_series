#!/usr/bin/env python3

"""Nagios check plugin for Dell | EMC² S-series switches, running OS10 firmware
   This check retrieve operational values from Dell specific SNMP MIBs :
   - hardware health
   - power unit status
   - fans status
   - temperatures
   For switching specific metrics (interface stats, etc.) it uses standard NET-SNMP MIBs, so
   you can use generic SNMP check as the excellent check_nwc_health from Consol Labs:
   https://labs.consol.de/nagios/check_nwc_health/

   cloned from  https://github.com/janit42/nagios_check_dell_s_series
   2018-09-04 - Eric Belhomme <rico-github@ricozome.net>

   Original author: Eric Belhomme
   Updated by: Alexander Bugl
"""

import sys
import argparse
import netsnmp

__author__ = 'Eric Belhomme'
__contact__ = 'rico-github@ricozome.net'
__version__ = '0.1.2'
__license__ = 'MIT'

nagiosStatus = {
    '0': 'OK',
    '1': 'WARNING',
    '2': 'CRITICAL',
    '3': 'UNKNOWN'
}

Os10CmnOperStatus = {
    '1': 'up',
    '2': 'down',
    '3': 'testing',
    '4': 'unknown',
    '5': 'dormant',
    '6': 'notPresent',
    '7': 'lowerLayerDown',
    '8': 'failed'
}

Os10ChassisDefType = {
    '1': 's6000on',
    '2': 's4048on',
    '3': 's4048Ton',
    '4': 's3048on',
    '5': 's6010on',
    '6': 's4148Fon',
    '7': 's4128Fon',
    '8': 's4148Ton',
    '9': 's4128Ton',
    '10': 's4148FEon',
    '11': 's4148Uon',
    '12': 's4200on',
    '13': 'mx5108Non',
    '14': 'mx9116Non',
    '15': 's5148Fon',
    '16': 'z9100on',
    '17': 's4248FBon',
    '18': 's4248FBLon',
    '19': 's4112Fon',
    '20': 's4112Ton',
    '21': 'z9264Fon',
    '22': 'z9224Fon',
    '23': 's5212Fon',
    '24': 's5224Fon',
    '25': 's5232Fon',
    '26': 's5248Fon',
    '27': 's5296Fon',
    '28': 'z9332Fon',
    '29': 'n3248TEon',
    '9999': 'unknown'
}

Os10CardOperStatus = {
    '1': 'ready',
    '2': 'cardMisMatch',
    '3': 'cardProblem',
    '4': 'diagMode',
    '5': 'cardAbsent',
    '6': 'offline'
}


def get_snmp_oper_status(snmp_session, snmp_oid, hw_type, warn, crit):
    ret_code = 0
    messages = []
    count_fail = 0
    varlist = netsnmp.VarList(netsnmp.Varbind(snmp_oid))
    vals = snmp_session.walk(varlist)

    if not vals:
        return 3, ['Unable to get SNMP metrics from server !'], []

    for index, item in enumerate(vals, start=1):
        status = int(item.decode("utf-8"))
        if status == 4:
            ret_code = 3
        else:
            if status != 1:
                count_fail += 1
        messages.append(f'{hw_type} #{str(index)} reported as {Os10CmnOperStatus.get(str(status))}')

    if ret_code != 3:
        if count_fail == 0:
            ret_code = 0
            messages.insert(0, f'All {hw_type} (s) OK')
        else:
            messages.insert(0, f'Failed or error found for {hw_type}')
            if count_fail < warn:
                ret_code = 1
            if count_fail < crit:
                ret_code = 2

    return ret_code, messages, []


def get_system_info(snmp_session):
    ret_code = 0
    messages = []
    varlist = netsnmp.VarList(
        netsnmp.Varbind('.1.3.6.1.2.1.1.5', 0), # sysName
        netsnmp.Varbind('.1.3.6.1.2.1.1.2', 0), # sysObjectId
        netsnmp.Varbind('.1.3.6.1.2.1.1.1', 0)) # sysDescr
    vals = [b.decode("utf-8") for b in snmp_session.get(varlist)]
    if not vals or None in vals:
        return 3, ['Unable to get SNMP metrics from server !'], []
    messages.append(f'{vals[0]} ( {vals[1]} )\n{vals[2]}')

    varlist = netsnmp.VarList(
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.2.1'), # chassis type
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.6.1'), # chassis hw rev.
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.4.1'), # chassis p/n
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.7.1')) # chassis service tag
    vals = [b.decode("utf-8") for b in snmp_session.get(varlist)]
    if not vals or None in vals:
        return 3, ['Unable to get SNMP metrics from server !'], []
    messages.append(f'Chassis: {Os10ChassisDefType.get(vals[0])} (rev. {vals[1]}) - p/n: {vals[2]} - ServiceTag: {vals[3]}')

    varlist = netsnmp.VarList(
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.4.1.3.1.1'), # card descr
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.4.1.8.1.1'), # card h/w rev.
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.4.1.6.1.1'), # card P/N
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.4.1.4.1.1'), # card status
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.4.1.9.1.1')) # card Service Tag
    vals = [b.decode("utf-8") for b in snmp_session.get(varlist)]
    if not vals or None in vals:
        return 3, ['Unable to get SNMP metrics from server !'], []
    card_status = int(vals[3])
    messages.append(f'Card: {vals[0]} (rev. {vals[1]}) - p/n: {vals[2]} - ServiceTag: {vals[4]} - Status: {Os10CardOperStatus.get(vals[3])}')

    if card_status != 1:
        if (card_status == 4 or card_status == 6) and ret_code < 1:
            ret_code = 1
        else:
            ret_code = 2

    return ret_code, messages, []


def get_temperatures(snmp_session, warn, crit):
    ret_code = 0
    messages = []
    perf_data = []
    varlist = netsnmp.VarList(
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.11.1'),   # chassis temp.
        netsnmp.Varbind('.1.3.6.1.4.1.674.11000.5000.100.4.1.1.4.1.5.1.1'))  # card temp.
    vals = list(map(lambda b: b.decode("utf-8"), snmp_session.get(varlist)))
    if not vals or None in vals:
        return 3, ['Unable to get SNMP metrics from server !'], []

    for index, temp in enumerate(vals, start=1):
        if int(temp) > crit and ret_code < 2:
            ret_code = 2
            messages.append(f'Temperature sensor at {str(temp)}°C exceeds critical threshold ({str(crit)}°C)')
        elif int(temp) > warn and ret_code < 1:
            ret_code = 1
            messages.append(f'Temperature sensor at {str(temp)}°C exceeds warning threshold ({str(warn)}°C)')
        else:
            messages.append(f'Temperature sensor at {str(temp)}°C')
            perf_data.append(f'temp{index}={str(temp)}°C;{str(warn)};{str(crit)}')
    if ret_code == 0:
        avg = sum(map(int, vals)) / len(vals)
        messages.insert(0, f'All temperature sensors OK with an average of {str(avg)}°C')

    return ret_code, messages, perf_data


def get_args():
    parser = argparse.ArgumentParser(description="Nagios check plugin for Dell|EMC S-series switches running OS10 firmware")
    parser.add_argument('--version', '-V', action='version', version=f"%(prog)s {__version__} - {__author__} <{__contact__}> - {__license__} license")
    parser.add_argument('-H', '--host', required=True, help='IP address')
    parser.add_argument('-C', '--community', default='public', help='SNMPv2 community')
    parser.add_argument('-m', '--mode', required=True, choices=['fans', 'power', 'health', 'temp'], help='Check mode')
    parser.add_argument('-w', '--warning', type=int, help='Warning threshold', default=50)
    parser.add_argument('-c', '--critical', type=int, help='Critical threshold', default=60)
    args = parser.parse_args()
    if args.mode == 'fans':
        args.warning = 1
        args.critical = 2
    elif args.mode == 'power':
        args.warning = 0
        args.critical = 1
    return args.host, args.community, args.mode, args.warning, args.critical


def main():
    ret_code = 3
    msg = []
    perf_data = []
    host, community, mode, warn, crit = get_args()
    snmp_session = netsnmp.Session(Version = 2, DestHost=host, Community=community)

    if mode == 'fans':
        # os10FanTrayOperStatus MIB
        ret_code, msg, perf_data = get_snmp_oper_status(snmp_session, '.1.3.6.1.4.1.674.11000.5000.100.4.1.2.2.1.4', 'fan', warn, crit)
    if mode == 'power':
        # os10PowerSupplyOperStatus MIB
        ret_code, msg, perf_data = get_snmp_oper_status(snmp_session, '.1.3.6.1.4.1.674.11000.5000.100.4.1.2.1.1.4', 'PSU', warn, crit)
    if mode == 'temp':
        ret_code, msg, perf_data = get_temperatures(snmp_session, warn, crit)
    if mode == 'health':
        ret_code, msg, perf_data = get_system_info(snmp_session)

    output = f'{nagiosStatus.get(str(ret_code))}: '
    if msg:
        output += '\n'.join(msg)
    if perf_data:
        output += " | " + " ".join(sorted(perf_data))
    print(output)

    sys.exit(ret_code)


if __name__ == '__main__':
    main()
