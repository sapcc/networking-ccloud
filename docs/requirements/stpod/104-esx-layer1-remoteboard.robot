*** Settings ***
Documentation     Swift node onboard remoteboard connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               Swift node remoteboard need connectivity to following networks:
...               - shared inband-mgmt (access), site-specific
...               
Default Tags      stPod      ESX     VMware

*** Test Cases ***

remoteboard connectivity
    Skip    Not implemented
