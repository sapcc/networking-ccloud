*** Settings ***
Documentation     Swift VM need connectivity a management VRF.
...
...               Controlplane management network should be a shared layer2 domain across controlplane VMs.
...               Controlplane VMs should be able to communicate within this layer2 domain without 
...               MAC address learning/resolution restrictions.
...               
...               Controlplane and Swift VMs share the same Controlplane management network.
...               
...               Management network is layer3, so it also needs to have a gateway.
...               
Library           SSHLibrary
Default Tags      stPod      Controlplane      Swift

*** Variables ***
${HOST} storage0.cc.qa-de-1.cloud.sap
${GATEWAY_IP} 10.1.1.1
${USERNAME} test
${PASSWORD} test

*** Test Cases ***

Management network gateway resolution
    Skip    Given Open Connection controlplane VM And Log In
    When ${output} = Execute Command "ping ${GATEWAY_IP}"
    Then Should Contain ${output} "64 bytes from ${GATEWAY_IP}"

*** Keywords ***
Open Connection controlplane VM And Log In
   Open Connection     ${HOST}
   Login               ${USERNAME}        ${PASSWORD}
