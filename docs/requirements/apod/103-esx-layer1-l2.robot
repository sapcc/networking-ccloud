*** Settings ***
Documentation     aPod node onboard L2 connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               aPod node L2 need connectivity to following networks:
...               - PX Domain 2 Service 1 Network (tagged)
...               - PX Domain 2 Service 2 Network (tagged)
...               - PX Domain 2 Service 3 Network (tagged)
...               
Library           SSHLibrary
