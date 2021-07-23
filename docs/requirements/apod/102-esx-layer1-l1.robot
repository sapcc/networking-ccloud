*** Settings ***
Documentation     aPod node onboard L1 connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               aPod node L1 need connectivity to following networks:
...               - aPOD Management Network (access), site-specific 
...               - aPOD VM Network (tagged), site-specific
...               - PX Domain 1 Service 1 Network (tagged)
...               - PX Domain 1 Service 2 Network (tagged)
...               - PX Domain 1 Service 3 Network (tagged)
...               
Library           SSHLibrary
