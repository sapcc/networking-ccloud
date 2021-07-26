*** Settings ***
Documentation     Swift VM need connectivity a management VRF.
...
...               Refer to Controlplane VM transit network requirements file.
...               
Library           SSHLibrary
Default Tags      stPod      Controlplane      Swift

*** Test Cases ***

Transit network internet connectivity
    Skip    Given Open Connection controlplane VM And Log In
    When ${output} = Execute Command "ping ${INTERNET_IP}"
    Then Should Contain ${output} "64 bytes from ${INTERNET_IP}"

Transit network SAP corp connectivity
    Skip    Given Open Connection controlplane VM And Log In
    When ${output} = Execute Command "ping ${CORP_IP}"
    Then Should Contain ${output} "64 bytes from ${CORP_IP}"

*** Keywords ***
Open Connection controlplane VM And Log In
   Open Connection     ${HOST}
   Login               ${USERNAME}        ${PASSWORD}
