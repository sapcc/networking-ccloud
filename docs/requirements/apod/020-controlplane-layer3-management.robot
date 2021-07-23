*** Settings ***
Documentation     Controlplane VM need connectivity a management VRF.
...
...               Management network is layer3, so it also needs to have a gateway.
...               
...               Management network requires internet connectivity.
...               
...               Management network requires connectivity to other SAP networks and all CC+1 regions.
...               
...               Controlplane traffic depends on Path MTU Discovery. Upstream device must generate 
...               an ICMP Frag-needed packet if Controlplane VM sends packet that is bigger than 
...               interface MTU of the upstream device. 
...               
Library           SSHLibrary
Default Tags      aPod      Controlplane

*** Variables ***
${HOST}            minion0.cc.qa-de-1.cloud.sap
${INTERNET_IP}     8.8.8.8
${CORP_IP}         <github-wdf-ip>
${USERNAME}        test
${PASSWORD}        test

*** Test Cases ***

Management network internet connectivity
    Skip    Given Open Connection controlplane VM And Log In
    When ${output} = Execute Command "ping ${INTERNET_IP}"
    Then Should Contain ${output} "64 bytes from ${INTERNET_IP}"

Management network SAP corp connectivity
    Skip    Given Open Connection controlplane VM And Log In
    When ${output} = Execute Command "ping ${CORP_IP}"
    Then Should Contain ${output} "64 bytes from ${CORP_IP}"

*** Keywords ***
Open Connection controlplane VM And Log In
   Open Connection     ${HOST}
   Login               ${USERNAME}        ${PASSWORD}
