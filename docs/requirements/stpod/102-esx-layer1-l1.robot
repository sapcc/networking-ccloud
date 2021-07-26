*** Settings ***
Documentation     Swift node onboard L1 connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               Swift node L1 need connectivity to following networks:
...               - aPOD Management Network (access), site-specific
...                 Network role: CC Management
...               
Default Tags      stPod      ESX     VMware

*** Test Cases ***

L1 connectivity
    Skip    Not implemented
