#Install-WindowsFeature -Name Hyper-V -ComputerName <computer_name> -IncludeManagementTools -Restart
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart

#Find existing network adapters by running the Get-NetAdapter cmdlet. Make a note of the network adapter 
#name that you want to use for the virtual switch.
Get-NetAdapter

#Create a virtual switch by using the New-VMSwitch cmdlet. 
#For example, to create an external virtual switch named ExternalSwitch, using the ethernet network adapter, 
#and with Allow management operating system to share this network adapter turned on, run the following command.
New-VMSwitch -name ExternalSwitch  -NetAdapterName Ethernet -AllowManagementOS $true

#To create an internal switch, run the following command.
New-VMSwitch -name InternalSwitch -SwitchType Internal

#To create an private switch, run the following command.
New-VMSwitch -name PrivateSwitch -SwitchType Private

#Create a NATed switch to be used in Azure HyperV 
#VMHyperVAddress:   172.16.9.1
#VMHyperVNetmask:   255.255.252.0 = 22
#VMHyperVNetwork:   172.16.8.0/22
#VMHyperVVMHyperVBroadcast: 172.16.11.255
#VMHyperVHostMin:   172.16.8.1
#VMHyperVHostMax:   172.16.11.254
#VMHyperVHosts/Net: 1022                  (Private Internet)
New-VMSwitch -Name "PC1-Switch" -SwitchType Internal
Get-VMSwitch -Name "PC1-Switch" 
New-NetNat -Name LocalNAT -InternalIPInterfaceAddressPrefix 172.16.10.0/24
#    Remove-NetNat -Name LocalNAT
Get-NetAdapter -Name "vEthernet (PC1-Switch)" | New-NetIPAddress -IPAddress 172.16.10.1 -AddressFamily IPv4 -PrefixLength 24


