# AzureHound v 0.0.3
# Author: Andy Robbins (@_wald0), Rohan Vazarkar (@cptjesus), Ryan Hausknecht (@haus3c)
# Copyright: SpecterOps, Inc. 2020

# Changelog:

# 0.0.1 - Initial build
# 0.0.2 - Changed all enumeration to include -All $True flag
# 0.0.3 - Now outputting JSON and collecting via Graph API

function Get-PrincipalMap {
	$Headers = Get-AzureGraphToken
	$AzureADUsers = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/users'
    $PrincipalMap = @{}
    $AzureADUsers.value | % {
        $PrincipalMap.add($_.id, $_.OnPremisesSecurityIdentifier)
    }
    $AzureADGroups = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/groups'
    $AzureADGroups.value | % {
        $PrincipalMap.add($_.id, $_.OnPremisesSecurityIdentifier)
    }

    $PrincipalMap
}

function Get-AzureGraphToken
{
    $APSUser = Get-AzContext *>&1 
    $resource = "https://graph.microsoft.com"
    $Token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
    $Headers = @{}
    $Headers.Add("Authorization","Bearer"+ " " + "$($token)")    
    $Headers
}

function New-Output($Coll, $Type) {
    Write-Host "Writing output for $($Type)"
    $Count = $Coll.Count
    if ($Count = $null) {
        $Coll = @($Coll)
    }
    $Output = New-Object PSObject
    $Meta = New-Object PSObject
    $Meta | Add-Member Noteproperty 'count' $Coll.Count
    $Meta | Add-Member Noteproperty 'type' "az$($Type)"
    $Meta | Add-Member Noteproperty 'version' 4
    $Output | Add-Member Noteproperty 'meta' $Meta
    $Output | Add-Member Noteproperty 'data' $Coll
    $FileName = "az" + $($Type) + ".json"
    $Output | ConvertTo-Json | Out-File -Encoding "utf8" -FilePath $FileName
}

function Invoke-AzureHound {

    $Headers = Get-AzureGraphToken
    $TenantObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/organization'
    $Tenant = $TenantObj.value
    $TenantId = $Tenant.id
    
    # Get users:
    $Coll = @()
	$AzureADUsersObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/users' 
    $AzureADUsers = $AzureADUsersObj.value
    $AzureADUsers | ForEach-Object {
        $User = $_		
        $CurrentUser = New-Object PSObject		
        $CurrentUser | Add-Member Noteproperty 'DisplayName' $User.displayname
        $CurrentUser | Add-Member Noteproperty 'UserPrincipalName' $User.UserPrincipalName
        $CurrentUser | Add-Member Noteproperty 'OnPremisesSecurityIdentifier' $User.OnPremisesSecurityIdentifier
        $CurrentUser | Add-Member Noteproperty 'ObjectID' $User.Id
        # if the current user is NOT an external user, add the tenantid property:
        if ($User.UserPrincipalName -NotMatch "#EXT#") {
            $CurrentUser | Add-Member Noteproperty 'TenantID' $TenantID
        }
        else {
            $CurrentUser | Add-Member Noteproperty 'TenantID' $null
        }
		
        $Coll += $CurrentUser
    }

    New-Output -Coll $Coll -Type "users"
      
    # Get groups:
    $Coll = @()
    $AzureADGroupsObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/groups'
    $AzureADGroups = $AzureADGroupsObj.value
    $AzureADGroups | ForEach-Object {
        $Group = $_
		
        $CurrentGroup = New-Object PSObject
		
        $CurrentGroup | Add-Member Noteproperty 'DisplayName' $Group.displayname
        $CurrentGroup | Add-Member Noteproperty 'OnPremisesSecurityIdentifier' $Group.OnPremisesSecurityIdentifier
        $CurrentGroup | Add-Member Noteproperty 'ObjectID' $Group.Id
        $CurrentGroup | Add-Member Noteproperty 'TenantID' $TenantId
		
        $Coll += $CurrentGroup
    }

    New-Output -Coll $Coll -Type "groups"
    
    $Coll = @()
    # Get tenants:
    $Tenant | ForEach-Object {
        $TenantX = $_

        $Current = New-Object PSObject
        $Current | Add-Member Noteproperty 'ObjectId' $TenantX.Id
        $Current | Add-Member NoteProperty 'DisplayName' $TenantX.DisplayName

        $Coll += $Current
    }

    New-Output -Coll $Coll -Type "tenants"

    $Coll = @()  
    # Get subscriptions:
    $Subscriptions = get-azsubscription *>&1
    $Subscriptions | ForEach-Object {
        $Sub = [PSCustomObject]@{
            Name           = $_.Name
            SubscriptionId = $_.SubscriptionId
            TenantId       = $_.TenantId
        }

        $Coll += $Sub
    }

    New-Output -Coll $Coll -Type "subscriptions"
    
    $Coll = @()
    # Get resource groups:
    $Subscriptions  | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
	
        Get-AzResourceGroup | ForEach-Object {
        
            $RG = $_
    	
            $id = $RG.resourceid
            $resourceSub = "$id".split("/", 4)[2]
    	
            $ResourceGroup = New-Object PSObject
    	
            $ResourceGroup | Add-Member Noteproperty 'ResourceGroupName' $RG.ResourceGroupName
            $ResourceGroup | Add-Member Noteproperty 'SubscriptionID' $resourceSub
            $ResourceGroup | Add-Member Noteproperty 'ResourceGroupID' $RG.ResourceId
    	
            $Coll += $ResourceGroup
        }
    }

    New-Output -Coll $Coll -Type "resourcegroups"
    
    $Coll = @()
    # Get VMs
    $Subscriptions | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
	
        Get-AzVM | ForEach-Object {
        
            $VM = $_
    	
            $RGName = $VM.ResourceGroupName
            $RGID = (Get-AzResourceGroup "$RGName").ResourceID
    	
            $id = $VM.id
            $resourceSub = "$id".split("/", 4)[2]
    	
            $AzVM = New-Object PSObject
            $AzVM | Add-Member Noteproperty 'AzVMName' $VM.Name
            $AzVM | Add-Member Noteproperty 'AZID' $VM.VmId
            $AzVM | Add-Member Noteproperty 'ResourceGroupName' $RGName
            $AzVM | Add-Member Noteproperty 'ResoucreGroupSub' $resourceSub
            $AzVM | Add-Member Noteproperty 'ResourceGroupID' $RGID
    	    $Coll += $AzVM
    	
        }
    }

    New-Output -Coll $Coll -Type "vms"
    
    $Coll = @()
    # Get KeyVaults
    $Subscriptions | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
	
        Get-AzKeyVault | ForEach-Object {
        
            $KeyVault = $_
    	
            $RGName = $KeyVault.ResourceGroupName
            $RGID = (Get-AzResourceGroup "$RGName").ResourceID
    	
            $id = $KeyVault.ResourceId
            $resourceSub = "$id".split("/", 4)[2]
    	
            $AzKeyVault = New-Object PSObject
            $AzKeyVault | Add-Member Noteproperty 'AzKeyVaultName' $KeyVault.VaultName
            $AzKeyVault | Add-Member Noteproperty 'AzKeyVaultID' $KeyVault.ResourceId
            $AzKeyVault | Add-Member Noteproperty 'ResourceGroupName' $RGName
            $AzKeyVault | Add-Member Noteproperty 'ResoucreGroupSub' $resourceSub
            $AzKeyVault | Add-Member Noteproperty 'ResourceGroupID' $RGID
    	
            $Coll += $AzKeyVault
        }
    }

    New-Output -Coll $Coll -Type "keyvaults"
    
    $Coll = @()
    # Get devices and their owners
    $DevicesObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/devices'
    $Devices = $DevicesObj.value
    $Devices | ForEach-Object {
        $Device = $_    	
        $DeviceId = $Device.id
        $OwnerData = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/devices/$DeviceId/registeredOwners"
        $Owner = $OwnerData.Value
        $AzureDeviceOwner = New-Object PSObject
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceDisplayname' $Device.Displayname
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceID' $Device.Id
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceOS' $Device.operatingSystem
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceOSVersion' $Device.operatingSystemVersion
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerDisplayName' $Owner.Displayname
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerID' $Owner.Id
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerType' $Owner.userType
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerOnPremID' $Owner.OnPremisesSecurityIdentifier
        $Coll += $AzureDeviceOwner  
    }

    New-Output -Coll $Coll -Type "devices"
    
    $Coll = @()
    # Get group owners
    $AzureADGroups | ForEach-Object {
        $Group = $_
        $GroupID = $_.ID
        $OwnersObj = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups/$GroupId/owners"
        $Owners = $OwnersObj.value
    	
        ForEach ($Owner in $Owners) {
            $datatype = $Owner.'@odata.type'
            $AZGroupOwner = New-Object PSObject
            $AZGroupOwner | Add-Member Noteproperty 'GroupName' $Group.DisplayName
            $AZGroupOwner | Add-Member Noteproperty 'GroupID' $GroupID
            $AZGroupOwner | Add-Member Noteproperty 'GroupOnPremID' $Group.OnPremisesSecurityIdentifier
            $AZGroupOwner | Add-Member Noteproperty 'OwnerName' $Owner.DisplayName
            $AZGroupOwner | Add-Member Noteproperty 'OwnerID' $Owner.ID
            $AZGroupOwner | Add-Member Noteproperty 'OwnerType' $datatype.split('.')[-1]
            $AZGroupOwner | Add-Member Noteproperty 'OwnerOnPremID' $Owner.OnPremisesSecurityIdentifier
            $Coll += $AZGroupOwner  
        }
    }

    New-Output -Coll $Coll -Type "groupowners"
    $Coll = @()
    
    # Get group members  
    $AzureADGroups | ForEach-Object {
        $Group = $_
        $GroupID = $_.ID
        $MembersObj = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups/$GroupID/members"
        $Members = $MembersObj.value
    	
        ForEach ($Member in $Members) {
            $datatype = $Member.'@odata.type'
            $AZGroupMember = New-Object PSObject
            $AZGroupMember | Add-Member Noteproperty 'GroupName' $Group.DisplayName
            $AZGroupMember | Add-Member Noteproperty 'GroupID' $GroupID
            $AZGroupMember | Add-Member Noteproperty 'GroupOnPremID' $Group.OnPremisesSecurityIdentifier
            $AZGroupMember | Add-Member Noteproperty 'MemberName' $Member.DisplayName
            $AZGroupMember | Add-Member Noteproperty 'MemberID' $Member.ID
            $AZGroupMember | Add-Member Noteproperty 'MemberType' $datatype.split('.')[-1]
            $AZGroupMember | Add-Member Noteproperty 'MemberOnPremID' $Member.OnPremisesSecurityIdentifier
            $Coll += $AZGroupMember
        }
    }
    New-Output -Coll $Coll -Type "groupmembers"
    
    # Inbound permissions against Virtual Machines
    # RoleDefinitionName 			RoleDefinitionId
    # ------------------			----------------
    # Contributor					b24988ac-6180-42a0-ab88-20f7382dd24c
    # Owner							8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator		18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    # Avere Contributor				4f8fab4f-1852-4a58-a46a-8eaf358af14a
    # Virtual Machine Contributor	9980e02c-c2be-4d73-94e8-173b1dc7cf3c
    
    $Coll = @()
    Get-AZSubscription | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Get-AzVm | ForEach-Object {
            $VM = $_
        	
            $VMID = $VM.id
            $VMGuid = $VM.VmId
        	
            $Roles = Get-AzRoleAssignment -scope $VMID
        	
            ForEach ($Role in $Roles) {
        	
                $ControllerType = $Role.ObjectType
        		$id = $Role.Id
                If ($ControllerType -eq "User") {
                    $Controller = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$id"
                    $OnPremID = $Controller.value.OnPremisesSecurityIdentifier
                }
        		
                If ($ControllerType -eq "Group") {
                    $Controller = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups/$id"
                    $OnPremID = $Controller.value.OnPremisesSecurityIdentifier
                }

				}
					
        	
                $VMPrivilege = New-Object PSObject
        		
                $VMPrivilege | Add-Member Noteproperty 'VMID' $VMGuid
                $VMPrivilege | Add-Member Noteproperty 'ControllerName' $Role.DisplayName
                $VMPrivilege | Add-Member Noteproperty 'ControllerID' $Role.ObjectID
                $VMPrivilege | Add-Member Noteproperty 'ControllerType' $Role.ObjectType
                $VMPrivilege | Add-Member Noteproperty 'ControllerOnPremID' $OnPremID
                $VMPrivilege | Add-Member Noteproperty 'RoleName' $Role.RoleDefinitionName
                $VMPrivilege | Add-Member Noteproperty 'RoleDefinitionId' $Role.RoleDefinitionId
        		
                $Coll += $VMPrivilege
            }
        }
    
    New-Output -Coll $Coll -Type "vmpermissions"
    
    # Inbound permissions against resource group
    # RoleDefinitionName 			RoleDefinitionId
    # ------------------			----------------
    # Owner							8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator		18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    $Coll = @()
    Get-AZSubscription | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
		
        Get-AzResourceGroup | ForEach-Object {
            $RG = $_
        	
            $RGID = $RG.ResourceId
        	
            $Roles = Get-AzRoleAssignment -scope $RGID
        	
            ForEach ($Role in $Roles) {
        	
                $ControllerType = $Role.ObjectType
        		$id = $Role.ObjectId
                If ($ControllerType -eq "User") {
                    $Controller = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$id"
                    $OnPremID = $Controller.value.OnPremisesSecurityIdentifier
                }
        		
                If ($ControllerType -eq "Group") {
                    $Controller = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups/$id"
                    $OnPremID = $Controller.value.OnPremisesSecurityIdentifier
                }
        	
                $RGPrivilege = New-Object PSObject        		
                $RGPrivilege | Add-Member Noteproperty 'RGID' $RGID
                $RGPrivilege | Add-Member Noteproperty 'ControllerName' $Role.DisplayName
                $RGPrivilege | Add-Member Noteproperty 'ControllerID' $Role.ObjectID
                $RGPrivilege | Add-Member Noteproperty 'ControllerType' $Role.ObjectType
                $RGPrivilege | Add-Member Noteproperty 'ControllerOnPremID' $OnPremID
                $RGPrivilege | Add-Member Noteproperty 'RoleName' $Role.RoleDefinitionName
                $RGPrivilege | Add-Member Noteproperty 'RoleDefinitionId' $Role.RoleDefinitionId
        		
                $Coll += $RGPrivilege
            }
        }
    }
    New-Output -Coll $Coll -Type "rgpermissions"
    
    # Inbound permissions against key vaults
    # RoleDefinitionName 			RoleDefinitionId
    # ------------------			----------------
    # Contributor					b24988ac-6180-42a0-ab88-20f7382dd24c
    # Owner							8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator		18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    # Key Vaults
    $Coll = @()
    Get-AZSubscription | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Get-AzKeyVault | ForEach-Object {
            $KeyVault = $_
        	
            $KVID = $KeyVault.ResourceId
        	
            $Roles = Get-AzRoleAssignment -scope $KVID
        	
            ForEach ($Role in $Roles) {
        	
                $ControllerType = $Role.ObjectType
        		$id = $Role.ObjectId
                If ($ControllerType -eq "User") {
                    $Controller = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$id"
                    $OnPremID = $Controller.value.OnPremisesSecurityIdentifier
                }
        		
                If ($ControllerType -eq "Group") {
                    $Controller = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/group/$id"
                    $OnPremID = $Controller.value.OnPremisesSecurityIdentifier
                }
        	
                $KVPrivilege = New-Object PSObject
        		
                $KVPrivilege | Add-Member Noteproperty 'KVID' $KVID
                $KVPrivilege | Add-Member Noteproperty 'ControllerName' $Role.DisplayName
                $KVPrivilege | Add-Member Noteproperty 'ControllerID' $Role.ObjectID
                $KVPrivilege | Add-Member Noteproperty 'ControllerType' $Role.ObjectType
                $KVPrivilege | Add-Member Noteproperty 'ControllerOnPremID' $Controller.value.OnPremisesSecurityIdentifier
                $KVPrivilege | Add-Member Noteproperty 'RoleName' $Role.RoleDefinitionName
                $KVPrivilege | Add-Member Noteproperty 'RoleDefinitionId' $Role.RoleDefinitionId
        		
                $Coll += $KVPrivilege
            }
        }
    }
    New-Output -Coll $Coll -Type "kvpermissions"
    
    $Coll = @()
    # KeyVault access policies
    Get-AZSubscription | ForEach-Object {
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Get-AzKeyVault | ForEach-Object {
            $KeyVault = $_
            $PrincipalMap = Get-PrincipalMap
            $KVID = $KeyVault.ResourceId
    		
            $AccessPolicies = Get-AzKeyVault -VaultName $_.VaultName | select -expand accesspolicies
        	
            ForEach ($Policy in $AccessPolicies) {
    		
                $ObjectOnPremID = $PrincipalMap[$Policy.ObjectID]
    		
                # Get Keys - PermissionsToKeys
                if ($Policy.PermissionsToKeys -Contains "Get") {
        	
                    $KVAccessPolicy = New-Object PSObject
        		
                    $KVAccessPolicy | Add-Member Noteproperty 'KVID' $KVID
                    $KVAccessPolicy | Add-Member Noteproperty 'ControllerID' $Policy.ObjectID
                    $KVAccessPolicy | Add-Member Noteproperty 'ObjectOnPremID' $ObjectOnPremID
                    $KVAccessPolicy | Add-Member Noteproperty 'Access' "GetKeys"
        		
                    $Coll += $KVAccessPolicy
    				
                }
                # Get Certificates - PermissionsToCertificates
                if ($Policy.PermissionsToCertificates -Contains "Get") {
        	
                    $KVAccessPolicy = New-Object PSObject
        		
                    $KVAccessPolicy | Add-Member Noteproperty 'KVID' $KVID
                    $KVAccessPolicy | Add-Member Noteproperty 'ControllerID' $Policy.ObjectID
                    $KVAccessPolicy | Add-Member Noteproperty 'ObjectOnPremID' $ObjectOnPremID
                    $KVAccessPolicy | Add-Member Noteproperty 'Access' "GetCertificates"
        		
                    $Coll += $KVAccessPolicy
    				
                }
                # Get Secrets - PermissionsToSecrets
                if ($Policy.PermissionsToSecrets -Contains "Get") {
        	
                    $KVAccessPolicy = New-Object PSObject
        		
                    $KVAccessPolicy | Add-Member Noteproperty 'KVID' $KVID
                    $KVAccessPolicy | Add-Member Noteproperty 'ControllerID' $Policy.ObjectID
                    $KVAccessPolicy | Add-Member Noteproperty 'ObjectOnPremID' $ObjectOnPremID
                    $KVAccessPolicy | Add-Member Noteproperty 'Access' "GetSecrets"
        		
                    $Coll += $KVAccessPolicy
    				
                }
            }
        }
    }
    New-Output -Coll $Coll -Type "kvaccesspolicies"
    
    # Abusable AZ Admin Roles
    $RoleObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/directoryRoles'
    $Roles = $RoleObj.value
    $Results = $Roles | ForEach-Object {
        
        $Role = $_
        $RoleId = $Role.ID
    	$RoleMembersObj = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/directoryRoles/$RoleId/members"
        $RoleMembers = $RoleMembersObj.Value
        ForEach ($Member in $RoleMembers) {
    	    $datatype = $Member.'@odata.type'
            $RoleMembership = New-Object PSObject
            $RoleMembership | Add-Member Noteproperty 'MemberName' $Member.DisplayName
            $RoleMembership | Add-Member Noteproperty 'MemberID' $Member.ID
            $RoleMembership | Add-Member Noteproperty 'MemberOnPremID' $Member.OnPremisesSecurityIdentifier
            $RoleMembership | Add-Member Noteproperty 'MemberUPN' $Member.UserPrincipalName
            $RoleMembership | Add-Member Noteproperty 'MemberType' $datatype.split('.')[-1]
            $RoleMembership | Add-Member Noteproperty 'RoleID' $Role.RoleTemplateId  	  	
            $RoleMembership
        }      
    }
   
    $UsersAndRoles = ForEach ($User in $Results) {
        $CurrentUser = $User.MemberID
        $CurrentUserName = $User.MemberName
        $CurrentUserRoles = ($Results | ? { $_.MemberID -eq $CurrentUser }).RoleID
        $CurrentUserUPN = $User.MemberUPN
        $CurrentUserOnPremID = $User.MemberOnPremID
    	
        $UserAndRoles = New-Object PSObject
        $UserAndRoles | Add-Member Noteproperty 'UserName' $CurrentUserName
        $UserAndRoles | Add-Member Noteproperty 'UserID' $CurrentUser
        $UserAndRoles | Add-Member Noteproperty 'UserOnPremID' $CurrentUserOnPremID
        $UserAndRoles | Add-Member Noteproperty 'UserUPN' $CurrentUserUPN
        $UserAndRoles | Add-Member Noteproperty 'RoleID' $CurrentUserRoles
    	
        $UserAndRoles
    }
    $UserRoles = $UsersAndRoles | Sort-Object -Unique -Property UserName
    $UsersWithRoles = $UserRoles.UserID
    $UsersWithoutRoles = $AzureADUsers | ? { $_.ID -NotIn $UsersWithRoles }
    
    $AuthAdminsList = @(
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
        '4a5d8f65-41da-4de4-8968-e035b65339cf'
    )
    	
    $HelpdeskAdminsList = @(
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
        '4a5d8f65-41da-4de4-8968-e035b65339cf'
    )
    	
    $PasswordAdminList = @(
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '966707d0-3269-4727-9be2-8c3a10f19b9d'
    )
    
    $UserAdminList = @(
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
        '4a5d8f65-41da-4de4-8968-e035b65339cf',
        'fe930be7-5e62-47db-91af-98c3a49a38b1'
    )
    
    #Privileged authentication administrator
    
    $PrivilegedAuthenticationAdmins = $UserRoles | ? { $_.RoleID -Contains '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' }
    $PrivilegedAuthenticationAdminRights = ForEach ($User in $PrivilegedAuthenticationAdmins) {
        $TargetUsers = $UserRoles | ? { $_.UserUPN -NotMatch "#EXT#" }
        # Privileged authentication admins can reset ALL user passwords, including global admins
        # You can't reset passwords for external users, which have "#EXT#" added to their UPN       
        ForEach ($TargetUser in $TargetUsers) {
        	
            	
            $PWResetRight = New-Object PSObject
        		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremId
        		
            $PWResetRight
        }
        	
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = New-Object PSObject
        		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.displayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.Id
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.onPremisesSecurityIdentifier
        		
            $PWResetRight
        }
    }
    
    $AuthenticationAdmins = $UserRoles | ? { $_.RoleID -Contains 'c4e39bd9-1100-46d3-8c65-fb160da0071f' }
    $AuthAdminsRights = ForEach ($User in $AuthenticationAdmins) {
    	    
        $TargetUsers = $UserRoles | ? { $AuthAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" }
        # You can't reset passwords for external users, which have "#EXT#" added to their UPN
    		
        ForEach ($TargetUser in $TargetUsers) {
    		
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremId
    		
            $PWResetRight
        }
    	
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.displayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.Id
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.onPremisesSecurityIdentifier
    		
            $PWResetRight
        }
    }
    
    $HelpdeskAdmins = $UserRoles | ? { $_.RoleID -Contains '729827e3-9c14-49f7-bb1b-9608f156bbb8' }
    $HelpdeskAdminsRights = ForEach ($User in $HelpdeskAdmins) {
    	    
        $TargetUsers = $UserRoles | ? { $HelpdeskAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" }
    		
        ForEach ($TargetUser in $TargetUsers) {
    		
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremId
    		
            $PWResetRight
        }
    	
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.displayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.Id
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.onPremisesSecurityIdentifier
    		
            $PWResetRight
        }
    
    }
    
    $PasswordAdmins = $UserRoles | ? { $_.RoleID -Contains '966707d0-3269-4727-9be2-8c3a10f19b9d' }
    $PasswordAdminsRights = ForEach ($User in $PasswordAdmins) {
    	    
        $TargetUsers = $UserRoles | ? { $PasswordAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" }
    		
        ForEach ($TargetUser in $TargetUsers) {
    		
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremId
    		
            $PWResetRight
        }
    	
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.displayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.Id
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.onPremisesSecurityIdentifier
    		
            $PWResetRight
        }
    	
    }
    
    $UserAccountAdmins = $UserRoles | ? { $_.RoleID -Contains 'fe930be7-5e62-47db-91af-98c3a49a38b1' }
    $UserAccountAdminsRights = ForEach ($User in $UserAccountAdmins) {
    	    
        $TargetUsers = $UserRoles | ? { $UserAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" }
    		
        ForEach ($TargetUser in $TargetUsers) {
    		
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremId
    		
            $PWResetRight
        }
    	
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = New-Object PSObject
    		
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.displayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.Id
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.onPremisesSecurityIdentifier
    		
            $PWResetRight
        }
    	
    }
    
    $CloudGroups = $AzureADGroups | ? { $_.OnPremisesSecurityIdentifier -eq $null } | Select DisplayName, ID
    
    # Intune administrator - 3a2c62db-5318-420d-8d74-23affee5d9d5 - Can add principals to cloud-resident security groups
    
    $IntuneAdmins = $UserRoles | ? { $_.RoleID -Contains '3a2c62db-5318-420d-8d74-23affee5d9d5' }
    $IntuneAdminsRights = ForEach ($User in $IntuneAdmins) {
    	    	
        ForEach ($TargetGroup in $CloudGroups) {
    		
            $GroupRight = New-Object PSObject
    		
            $GroupRight | Add-Member Noteproperty 'UserName' $User.UserName
            $GroupRight | Add-Member Noteproperty 'UserID' $User.UserID
            $GroupRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $GroupRight | Add-Member Noteproperty 'TargetGroupName' $TargetGroup.DisplayName
            $GroupRight | Add-Member Noteproperty 'TargetGroupID' $TargetGroup.ID
    		
            $GroupRight
        }
    }
    
    # Groups administrator - Can add principals to cloud-resident security groups
    
    $GroupsAdmins = $UserRoles | ? { $_.RoleID -Contains 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
    $GroupsAdminsRights = ForEach ($User in $GroupsAdmins) {
    	    	
        ForEach ($TargetGroup in $CloudGroups) {
    		
            $GroupRight = New-Object PSObject
    		
            $GroupRight | Add-Member Noteproperty 'UserName' $User.UserName
            $GroupRight | Add-Member Noteproperty 'UserID' $User.UserID
            $GroupRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $GroupRight | Add-Member Noteproperty 'TargetGroupName' $TargetGroup.DisplayName
            $GroupRight | Add-Member Noteproperty 'TargetGroupID' $TargetGroup.ID
    		
            $GroupRight
        }
    }
     
    
    # Global Admin - has full control of everything in the tenant
    
    $GlobalAdmins = $UserRoles | ? { $_.RoleID -Contains '62e90394-69f5-4237-9190-012177145e10' }
    $GlobalAdminsRights = ForEach ($User in $GlobalAdmins) {	
    		
        $GlobalAdminRight = New-Object PSObject
    		
        $GlobalAdminRight | Add-Member Noteproperty 'UserName' $User.UserName
        $GlobalAdminRight | Add-Member Noteproperty 'UserID' $User.UserID
        $GlobalAdminRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
        $GlobalAdminRight | Add-Member Noteproperty 'TenantDisplayName' $Tenant.DisplayName
        #$GlobalAdminRight | Add-Member Noteproperty 'TenantVerifiedDomains' $Tenants.VerifiedDomains
        $GlobalAdminRight | Add-Member Noteproperty 'TenantID' $Tenant.ID
    		
        $GlobalAdminRight
    }
    
    # Privilege role administrator
    # Can add role assignments to any other user including themselves
    
    $PrivRoleColl = @()
    $PrivilegedRoleAdmins = $UserRoles | ? { $_.RoleID -Contains 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
    $PrivilegedRoleAdminRights = ForEach ($User in $PrivilegedRoleAdmins) {	
    		
        $PrivilegedRoleAdminRight = New-Object PSObject
    		
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'UserName' $User.UserName
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'UserID' $User.UserID
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'TenantDisplayName' $Tenant.DisplayName
        #$PrivilegedRoleAdminRight | Add-Member Noteproperty 'TenantVerifiedDomains' $TenantDetails.VerifiedDomains
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'TenantID' $Tenant.ID
    		
        $PrivRoleColl += $PrivilegedRoleAdminRight
    }
    
    $Coll = @()
    $PrivilegedAuthenticationAdminRights | ForEach-Object {
        $Coll += $_
    }
    $AuthAdminsRights | ForEach-Object {
        $Coll += $_
    }
    $HelpdeskAdminsRights | ForEach-Object {
        $Coll += $_
    }
    $PasswordAdminsRights | ForEach-Object {
        $Coll += $_
    }
    $UserAccountAdminsRights | ForEach-Object {
        $Coll += $_
    }
    New-Output -Coll $Coll -Type "pwresetrights"
    # $PrivilegedAuthenticationAdminRights | Export-CSV -NoTypeInformation -Append pwresetrights.csv
    # $AuthAdminsRights | Export-CSV -NoTypeInformation -Append pwresetrights.csv
    # $HelpdeskAdminsRights | Export-CSV -NoTypeInformation -Append pwresetrights.csv
    # $PasswordAdminsRights | Export-CSV -NoTypeInformation -Append pwresetrights.csv
    # $UserAccountAdminsRights | Export-CSV -NoTypeInformation -Append pwresetrights.csv
    
    $Coll = @()
    $IntuneAdminsRights | ForEach-Object {
        $Coll += $_
    }
    $GroupsAdminsRights | ForEach-Object {
        $Coll += $_
    }
    New-Output -Coll $Coll -Type "groupsrights"
    # $IntuneAdminsRights | Export-CSV -NoTypeInformation -Append groupsrights.csv
    # $GroupsAdminsRights | Export-CSV -NoTypeInformation -Append groupsrights.csv
    
    New-Output -Coll $GlobalAdminsRights -Type "globaladminrights"
    New-Output -Coll $PrivRoleColl -Type "privroleadminrights"
    
    # $GlobalAdminsRights | Export-CSV -NoTypeInformation globaladminrights.csv
    # $PrivilegedRoleAdminRights | Export-CSV -NoTypeInformation privroleadminrights.csv



    # Get app owners
    $AzureADApplicationObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/applications'
    $AzureADApplication = $AzureADApplicationObj.value 
    $AzureADApplication | ForEach-Object {

        $AppId = $_.AppId
        $ObjectId = $_.Id

        $AppOwnersObj = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/applications/$ObjectId/owners"
        $AppOwners = $AppOwnersObj.value
	
        ForEach ($Owner in $AppOwners) {
	    
            $AzureAppOwner = New-Object PSObject
		
            $AzureAppOwner | Add-Member Noteproperty 'AppId' $AppId
            $AzureAppOwner | Add-Member Noteproperty 'AppObjectId' $ObjectId
            $AzureAppOwner | Add-Member Noteproperty 'OwnerID' $Owner.Id
            $AzureAppOwner | Add-Member Noteproperty 'OwnerType' $Owner.ObjectType
            $AzureAppOwner | Add-Member Noteproperty 'OwnerOnPremID' $Owner.OnPremisesSecurityIdentifier
		
            $AzureAppOwner
		
        }
    }

# Get MS-PIM role configurations

# Get-AzureADMSPrivilegedRoleAssignment -ProviderId 'aadRoles' -ResourceId '3f06a216-e798-47d3-9b06-31482aa5a648' | % {
#     $PrivilegedRoleAdmins = $_ | ? { $_.RoleDefinitionId -Contains 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
#     $PrivilegedRoleAdmins
	
#     $GlobalAdmins = $_ | ? { $_.RoleDefinitionId -Contains '62e90394-69f5-4237-9190-012177145e10' }
#     $GlobalAdmins
	
#     $IntuneAdmins = $_ | ? { $_.RoleID -Contains '3a2c62db-5318-420d-8d74-23affee5d9d5' }
#     $IntuneAdmins
	
#     $GroupsAdmins = $_ | ? { $_.RoleID -Contains 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
#     $GroupsAdmins
	
#     $UserAccountAdmins = $_ | ? { $_.RoleID -Contains 'fe930be7-5e62-47db-91af-98c3a49a38b1' }
#     $UserAccountAdmins
	
#     $PasswordAdmins = $_ | ? { $_.RoleID -Contains '966707d0-3269-4727-9be2-8c3a10f19b9d' }
#     $PasswordAdmins
	
#     $HelpdeskAdmins = $_ | ? { $_.RoleID -Contains '729827e3-9c14-49f7-bb1b-9608f156bbb8' }
#     $HelpdeskAdmins
	
#     $AuthenticationAdmins = $_ | ? { $_.RoleID -Contains 'c4e39bd9-1100-46d3-8c65-fb160da0071f' }
#     $AuthenticationAdmins
	
#     $PrivilegedAuthenticationAdmins = $_ | ? { $_.RoleID -Contains '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' }
#     $PrivilegedAuthenticationAdmins

Write-Host "Compressing files"
Compress-Archive *.json -DestinationPath azurecollection.zip
rm *.json
	
}



function Get-AzureADAuditSignInLogs2 {
    Param(
        #[parameter(Mandatory=$false)]
        #[System.Boolean]
        #$All,
        [parameter(Mandatory = $false)]
        [parameter(ParameterSetName = 'GetQuery')]
        [System.Int32]
        $Top,
        [parameter(Mandatory = $false)]
        [parameter(ParameterSetName = 'GetQuery')]
        [System.String]
        $Filter
    )
    #Find token from previous 'Connect-AzureAD' command
    #https://stackoverflow.com/questions/49569712/exposing-the-connection-token-from-connect-azuread
    $accessToken = $null
    try {
        $accessToken = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken'].AccessToken
    }
    catch {
        Throw 'Please run Connect-AzureAD to connect prior to running this command'
    }

    if ($accessToken) {
        $querystringparams = @{}

        if ($Top) {
            $querystringparams['$top'] = $Top
        }

        if ($Filter) {
            $querystringparams['$filter'] = $Filter
        }

        $domain = 'graph.microsoft.com'
        $url = "https://$domain/beta/auditLogs/signIns"
    
        if ($querystringparams.Count -gt 0) {
            Add-Type -AssemblyName System.Web
            $url = $url + "?" + (($querystringparams.Keys | % { [System.Web.HttpUtility]::UrlEncode($_) + "=" + [System.Web.HttpUtility]::UrlEncode($querystringparams[$_]) }) -join '&')
        }

        $headers = @{
            'Authorization'   = "Bearer $accessToken";
            'Host'            = $domain;
            #'client-request-id' = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx';
            'Accept'          = 'application/json';
            'cmdlet-name'     = 'Get-AzureADAuditSignInLogs'
            'Accept-Encoding' = 'gzip, deflate'
        }

        (Invoke-RestMethod -Method Get -Uri $url -Headers $headers).value
    }
}

function Get-AzureADSignInLogs3 {
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory = $False, Position = 2)] [Int32]  $Top,
        [parameter(Mandatory = $False, Position = 3)] [String] $Filter,
        [parameter(Mandatory = $False, Position = 4)] [Switch] $All
    )

    $domain = 'graph.microsoft.com'
    $url = "https://$domain/beta/auditLogs/signIns"

    $querystringparams = @{}
    if ($Top) {
        $querystringparams['$top'] = $Top
    }

    if ($Filter) {
        $querystringparams['$filter'] = $Filter
    }

    if ($querystringparams.Count -gt 0) {
        Add-Type -AssemblyName System.Web
        $url = $url + "?" + (($querystringparams.Keys | Foreach-Object { [System.Web.HttpUtility]::UrlEncode($_) + "=" + [System.Web.HttpUtility]::UrlEncode($querystringparams[$_]) }) -join '&')
    }

    $accessToken = $null
    try {
        $accessToken = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken'].AccessToken
    }
    catch {
        Throw 'Please run Connect-AzureAD to connect prior to running this command'
    }

    $headers = @{
        'Authorization'   = "Bearer $accessToken";
        'Host'            = $domain;
        'Accept'          = 'application/json';
        'cmdlet-name'     = 'Get-AzureADAuditSignInLogs'
        'Accept-Encoding' = 'gzip, deflate'
    }

    if ($All) {
        do {
            Write-Verbose "Sending POST to $url"
            $pageResults = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
            [array]$results += $pageResults.value
            $url = $pageResults."@odata.nextLink"
        } until ($null -eq $url)
    }
    else {
        Write-Verbose "Sending POST to $url"
        $results = (Invoke-RestMethod -Method Get -Uri $url -Headers $headers).value
    }
    return $results
}
Invoke-AzureHound
