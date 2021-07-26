*** Settings ***
Documentation     aPod node onboard remoteboard connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               aPod node remoteboard need connectivity to following networks:
...               - shared inband-mgmt (access), site-specific
...                 Network role: CC Console
...               
Default Tags      aPod      ESX     VMware

*** Test Cases ***

remoteboard connectivity
    Skip    Not implemented
