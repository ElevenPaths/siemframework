#!/usr/bin/env python3

# QRadar information user database AQL

# %%%%%%%%%%% Libraries %%%%%%%%%%%#

from globals import https
from globals import SEPARATOR
from globals import qradar_messages

from colorama import Fore, Style
from qradar4py.api import QRadarApi


# %%%%%%%%%% Functions %%%%%%%%%#


def qradar_usersdb(ip, port):

    api = input("[!] Enter API Key of QRadar: ")
    url = https + ip + ":" + str(port)
    api = QRadarApi(url, api, version='9.1', verify=False)

    status, resp = api.ariel.post_searches(
        query_expression='Select username, count(*) as UserNameCount'
                         ' FROM events GROUP BY username')

    idsearch = resp['search_id']

    status, resp = api.ariel.get_searches_results_by_search_id(
        search_id=idsearch)

    if status == 200:
        for dbs in resp.keys():
            ops = 0
            qradar_messages(6)
            while ops < len(resp[dbs]):
                name = resp[dbs][ops]['username']
                print(Style.RESET_ALL + "[!] User Database: " +
                      Fore.RED + Style.BRIGHT + str(name))
                print(Style.RESET_ALL + SEPARATOR)
                ops += 1
    else:
        qradar_messages(7)

# %%%%%%%%%% The End %%%%%%%%%%#
