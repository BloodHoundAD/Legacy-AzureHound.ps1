# AzureHound Beta
# Authors: Andy Robbins (@_wald0), Rohan Vazarkar (@cptjesus), Ryan Hausknecht (@haus3c)
# Copyright: SpecterOps, Inc. 2020

function Get-PrincipalMap {

    $PrincipalMap = @{}
    Get-AzureADUser -All $True | % {
        $PrincipalMap.add($_.objectid, $_.OnPremisesSecurityIdentifier)
    }
    Get-AzureADGroup -All $True | % {
        $PrincipalMap.add($_.objectid, $_.OnPremisesSecurityIdentifier)
    }
    $PrincipalMap
}
function Connect-AADUser {
    $ConnectionTest = try{ [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken']}
    catch{"Error"}
    If($ConnectionTest -eq 'Error'){ 
    $context = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
    $aadToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.windows.net").AccessToken
    Connect-AzureAD -AadAccessToken $aadToken -AccountId $context.Account.Id -TenantId $context.tenant.id}
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

$Verbose = $True
function Write-Info ($Message) {
    If ($Verbose -eq $True) {
        Write-Host $Message
    }
}

function New-Output($Coll, $Type, $Directory) {
    
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
    $FileName = $Directory + "\" + $date + "-" + "az" + $($Type) + ".json"
    $Output | ConvertTo-Json | Out-File -Encoding "utf8" -FilePath $FileName  
}

function Invoke-AzureHound {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)][String]$TenantID = $null,
    [Parameter(Mandatory=$False)][String]$OutputDirectory = $(Get-Location),[ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$False)][Switch]$Install = $null)

    if ($Install){
      Install-Module -Name Az -AllowClobber
      Install-module -Name AzureADPreview -AllowClobber
    }

    $Modules = Get-InstalledModule
    if ($Modules.Name -notcontains 'Az.Accounts' -and $Modules.Name -notcontains 'AzureAD'){ 
      Write-Host "AzureHound requires the 'Az' and 'Azure AD PowerShell module, please install by using the -Install switch."
      exit
    }

    $date = get-date -f yyyyMMddhhmmss

    #Login Check
    $APSUser = Get-AzContext *>&1 
    if ($APSUser -eq $null){
        Connect-AzAccount
        $APSUser = Get-AzContext *>&1
        if ($APSUser -eq $null){
            Read-Host -Prompt "Login via Az PS Module failed."
            exit
            }
    }
    Connect-AADUser
    $Headers = Get-AzureGraphToken

    If(!$TenantID){
        $TenantObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/organization'
        $Tenant = $TenantObj.value
        $TenantId = $Tenant.id
	}

    # Enumerate users
    $Coll = @()
    Write-Info "Building users object, this may take a few minutes."
	$AADUsers = Get-AzureADUser -All $True | Select UserPrincipalName,OnPremisesSecurityIdentifier,ObjectID,TenantId
    $TotalCount = $AADUsers.Count
    Write-Host "Done building users object, processing ${TotalCount} users"
    $Progress = 0
    $AADUsers | ForEach-Object {

        $User = $_
        $DisplayName = ($User.UserPrincipalName).Split('@')[0]

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Host "Processing users: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user: ${DisplayName}"
        } else {
            If (($Progress % 1000) -eq 0) {
                Write-Host "Processing users: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user: ${DisplayName}"
            } 
        }

        $CurrentUserTenantID = $null
        If ($User.UserPrincipalName -NotMatch "#EXT#") {
            $CurrentUserTenantID = $TenantID
        }

        $CurrentUser = [PSCustomObject]@{
            DisplayName                     =   $User.displayname
            UserPrincipalName               =   $User.UserPrincipalName
            OnPremisesSecurityIdentifier    =   $User.OnPremisesSecurityIdentifier
            ObjectID                        =   $User.ObjectID
            TenantID                        =   $CurrentUserTenantID
        }
        
        $Coll += $CurrentUser
    }
    New-Output -Coll $Coll -Type "users" -Directory $OutputDirectory

    # Enumerate groups
    $Coll = @()
    Write-Info "Building groups object, this may take a few minutes."
    $AADGroups = Get-AzureADGroup -All $True | ?{$_.SecurityEnabled -Match "True"}
    $TotalCount = $AADGroups.Count
    Write-Info "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.displayname

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }
        
        <#$CurrentGroup = New-Object PSObject
        
        $CurrentGroup | Add-Member Noteproperty 'DisplayName' $Group.displayname
        $CurrentGroup | Add-Member Noteproperty 'OnPremisesSecurityIdentifier' $Group.OnPremisesSecurityIdentifier
        $CurrentGroup | Add-Member Noteproperty 'ObjectID' $Group.ObjectID
        $CurrentGroup | Add-Member Noteproperty 'TenantID' $TenantID#>

        $CurrentGroup = [PSCustomObject]@{
            DisplayName                    =  $Group.displayname
            OnPremisesSecurityIdentifier   =  $Group.OnPremisesSecurityIdentifier
            ObjectID                       =  $Group.ObjectID
            TenantID                       =  $TenantID
        }
        
        $Coll += $CurrentGroup
    }
    New-Output -Coll $Coll -Type "groups" -Directory $OutputDirectory
    
    # Enumerate tenants:
    $Coll = @()
    Write-Info "Building tenant(s) object."
    $AADTenants = Get-AzureADTenantDetail
    $TotalCount = $AADTenants.Count
    If ($TotalCount -gt 1) {
        Write-Info "Done building tenant object, processing ${TotalCount} tenant"
    } else {
        Write-Info "Done building tenants object, processing ${TotalCount} tenants"
    }
    $Progress = 0
    $AADTenants | ForEach-Object {

        $Tenant = $_
        $DisplayName = $Tenant.DisplayName

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
            } 
        }

        <#$Current = New-Object PSObject
        $Current | Add-Member Noteproperty 'ObjectId' $Tenant.ObjectId
        $Current | Add-Member NoteProperty 'DisplayName' $Tenant.DisplayName#>

        $Current = [PSCustomObject]@{
            ObjectID    = $Tenant.ObjectId
            DisplayName = $Tenant.DisplayName
        }

        $Coll += $Current
    }
    New-Output -Coll $Coll -Type "tenants" -Directory $OutputDirectory

    # Enumerate subscriptions:
    $Coll = @()
    Write-Info "Building subscription(s) object."
    $AADSubscriptions = Get-AzSubscription
    $TotalCount = $AADSubscriptions.Count
    If ($TotalCount -gt 1) {
        Write-Info "Done building subscription object, processing ${TotalCount} subscription"
    } else {
        Write-Info "Done building subscriptions object, processing ${TotalCount} subscriptions"
    }
    $Progress = 0
    $AADSubscriptions | ForEach-Object {

        $Subscription = $_
        $DisplayName = $Subscription.Name

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
            } 
        }

        <#$Current = New-Object PSObject
        $Current | Add-Member Noteproperty 'Name' $Subscription.Name
        $Current | Add-Member NoteProperty 'SubscriptionId' $Subscription.SubscriptionId
        $Current | Add-Member NoteProperty 'TenantId' $Subscription.TenantId#>

        $Current = [PSCustomObject]@{
            Name            = $Subscription.Name
            SubscriptionId  = $Subscription.SubscriptionId
            TenantId        = $Subscription.TenantId
        }

        $Coll += $Current
    }
    New-Output -Coll $Coll -Type "subscriptions" -Directory $OutputDirectory
    
    # Enumerate resource groups:
    $Coll = @()
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building resource groups object for subscription ${SubDisplayName}"
        $AADResourceGroups = Get-AzResourceGroup
        $TotalCount = $AADResourceGroups.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building resource group object, processing ${TotalCount} resource group"
        } else {
            Write-Info "Done building resource groups object, processing ${TotalCount} resource groups"
        }
        $Progress = 0
    
        $AADResourceGroups | ForEach-Object {

            $RG = $_
            $DisplayName = $RG.ResourceGroupName

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
                } 
            }
        
            $id = $RG.resourceid
            $resourceSub = "$id".split("/", 4)[2]
        
            <#$ResourceGroup = New-Object PSObject
            $ResourceGroup | Add-Member Noteproperty 'ResourceGroupName' $RG.ResourceGroupName
            $ResourceGroup | Add-Member Noteproperty 'SubscriptionID' $resourceSub
            $ResourceGroup | Add-Member Noteproperty 'ResourceGroupID' $RG.ResourceId#>

            $ResourceGroup = [PSCustomObject]@{
                ResourceGroupName   = $RG.ResourceGroupName
                SubscriptionID      = $resourceSub
                ResourceGroupID     = $RG.ResourceId
            }
        
            $Coll += $ResourceGroup
        }
    }

    New-Output -Coll $Coll -Type "resourcegroups" -Directory $OutputDirectory

    $Coll = @()
    # Get VMs
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building VMs object for subscription ${SubDisplayName}"
        $AADVirtualMachines = Get-AzVM
        $TotalCount = $AADVirtualMachines.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building VM object, processing ${TotalCount} virtual machine"
        } else {
            Write-Info "Done building VMs object, processing ${TotalCount} virtual machines"
        }
        $Progress = 0
    
        $AADVirtualMachines | ForEach-Object {
        
            $VM = $_
            $DisplayName = $VM.Name

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current virtual machine: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current virtual machine: ${DisplayName}"
                } 
            }
        
            $RGName = $VM.ResourceGroupName
            $RGID = (Get-AzResourceGroup "$RGName").ResourceID
        
            $id = $VM.id
            $resourceSub = "$id".split("/", 4)[2]
        
            <#$AzVM = New-Object PSObject
            $AzVM | Add-Member Noteproperty 'AzVMName' $VM.Name
            $AzVM | Add-Member Noteproperty 'AZID' $VM.VmId
            $AzVM | Add-Member Noteproperty 'ResourceGroupName' $RGName
            $AzVM | Add-Member Noteproperty 'ResoucreGroupSub' $resourceSub
            $AzVM | Add-Member Noteproperty 'ResourceGroupID' $RGID#>

            $AzVM = [PSCustomObject]@{
                AzVMName = $VM.Name
                AZID = $VM.VmId
                ResourceGroupName = $RGName
                ResoucreGroupSub = $resourceSub
                ResourceGroupID = $RGID
            }

            $Coll += $AzVM
        
        }
    }
    New-Output -Coll $Coll -Type "vms" -Directory $OutputDirectory
    
    $Coll = @()
    # Get KeyVaults
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building key vaults object for subscription ${SubDisplayName}"
    
        $AADKeyVaults = Get-AzKeyVault
        $TotalCount = $AADKeyVaults.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building key vaults object, processing ${TotalCount} key vaults"
        } else {
            Write-Info "Done building key vault object, processing ${TotalCount} key vault"
        }
        $Progress = 0
        
        $AADKeyVaults | ForEach-Object {
        
            $KeyVault = $_
            $DisplayName = $KeyVault.Name

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
                } 
            }
        
            $RGName = $KeyVault.ResourceGroupName
            $RGID = (Get-AzResourceGroup "$RGName").ResourceID
        
            $id = $KeyVault.ResourceId
            $resourceSub = "$id".split("/", 4)[2]
        
            <#$AzKeyVault = New-Object PSObject
            $AzKeyVault | Add-Member Noteproperty 'AzKeyVaultName' $KeyVault.VaultName
            $AzKeyVault | Add-Member Noteproperty 'AzKeyVaultID' $KeyVault.ResourceId
            $AzKeyVault | Add-Member Noteproperty 'ResourceGroupName' $RGName
            $AzKeyVault | Add-Member Noteproperty 'ResoucreGroupSub' $resourceSub
            $AzKeyVault | Add-Member Noteproperty 'ResourceGroupID' $RGID#>

            $AzKeyVault = [PSCustomObject]@{
                AzKeyVaultName      = $KeyVault.VaultName
                AzKeyVaultID        = $KeyVault.ResourceId
                ResourceGroupName   = $RGName
                ResoucreGroupSub    = $resourceSub
                ResourceGroupID     = $RGID
            }
        
            $Coll += $AzKeyVault
        }
    }
    New-Output -Coll $Coll -Type "keyvaults" -Directory $OutputDirectory
    
    $Coll = @()
    # Get devices and their owners
    Write-Info "Building devices object."
    $AADDevices =  Get-AzureADDevice | ?{$_.DeviceOSType -Match "Windows" -Or $_.DeviceOSType -Match "Mac"}
    $TotalCount = $AADDevices.Count
    Write-Info "Done building devices object, processing ${TotalCount} devices"
    $Progress = 0
    $AADDevices | ForEach-Object {

        $Device = $_
        $DisplayName = $Device.DisplayName

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
            } 
        }
        
        $Owner = Get-AzureADDeviceRegisteredOwner -ObjectID $Device.ObjectID
        
        <#$AzureDeviceOwner = New-Object PSObject
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceDisplayname' $Device.Displayname
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceID' $Device.ObjectID
        $AzureDeviceOwner | Add-Member Noteproperty 'DeviceOS' $Device.DeviceOSType
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerDisplayName' $Owner.Displayname
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerID' $Owner.ObjectID
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerType' $Owner.ObjectType
        $AzureDeviceOwner | Add-Member Noteproperty 'OwnerOnPremID' $Owner.OnPremisesSecurityIdentifier#>

        $AzureDeviceOwner = [PSCustomObject]@{
            DeviceDisplayname   = $Device.Displayname
            DeviceID            = $Device.ObjectID
            DeviceOS            = $Device.DeviceOSType
            OwnerDisplayName    = $Owner.Displayname
            OwnerID             = $Owner.ObjectID
            OwnerType           = $Owner.ObjectType
            OwnerOnPremID       = $Owner.OnPremisesSecurityIdentifier
        }

        $Coll += $AzureDeviceOwner
    }
    New-Output -Coll $Coll -Type "devices" -Directory $OutputDirectory
    
    # Enumerate group owners
    $Coll = @()
    Write-Info "Checking if groups object is already built..."
    If ($AADGroups.Count -eq 0) {
        Write-Info "Creating groups object, this may take a few minutes."
        $AADGroups = Get-AzureADGroup -All $True | ?{$_.SecurityEnabled -Match "True"}
    }
    $TargetGroups = $AADGroups | ?{$_.OnPremisesSecurityIdentifier -eq $null}
    $TotalCount = $TargetGroups.Count
    Write-Info "Done building target groups object, processing ${TotalCount} groups"
    $Progress = 0
    $TargetGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.DisplayName

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing group ownerships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing group ownerships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        $GroupID = $_.ObjectID
        $Owners = Get-AzureADGroupOwner -ObjectId "$GroupID"
        
        ForEach ($Owner in $Owners) {
            <#$AZGroupOwner = New-Object PSObject
            $AZGroupOwner | Add-Member Noteproperty 'GroupName' $Group.DisplayName
            $AZGroupOwner | Add-Member Noteproperty 'GroupID' $GroupID
            $AZGroupOwner | Add-Member Noteproperty 'GroupOnPremID' $Group.OnPremisesSecurityIdentifier
            $AZGroupOwner | Add-Member Noteproperty 'OwnerName' $Owner.DisplayName
            $AZGroupOwner | Add-Member Noteproperty 'OwnerID' $Owner.ObjectID
            $AZGroupOwner | Add-Member Noteproperty 'OwnerType' $Owner.ObjectType
            $AZGroupOwner | Add-Member Noteproperty 'OwnerOnPremID' $Owner.OnPremisesSecurityIdentifier#>

            $AZGroupOwner = [PSCustomObject]@{
                GroupName       = $Group.DisplayName
                GroupID         = $GroupID
                OwnerName       = $Owner.DisplayName
                OwnerID         = $Owner.ObjectID
                OwnerType       = $Owner.ObjectType
                OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
            }
            $Coll += $AZGroupOwner   
        }   
    }
    New-Output -Coll $Coll -Type "groupowners" -Directory $OutputDirectory

    # Enumerate group members
    $Coll = @()
    Write-Info "Checking if groups object is already built..."
    If ($AADGroups.Count -eq 0) {
        Write-Info "Creating groups object, this may take a few minutes."
        $AADGroups = Get-AzureADGroup -All $True | ?{$_.SecurityEnabled -Match "True"}
    }
    $TotalCount = $AADGroups.Count
    Write-Info "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.DisplayName

        $Progress += 1
        $ProgressPercentage = ($Progress / $TotalCount) * 100

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        $GroupID = $_.ObjectID
        $Members = Get-AzureADGroupMember -ObjectId "$GroupID"
        
        ForEach ($Member in $Members) {
            <#$AZGroupMember = New-Object PSObject
            $AZGroupMember | Add-Member Noteproperty 'GroupName' $Group.DisplayName
            $AZGroupMember | Add-Member Noteproperty 'GroupID' $GroupID
            $AZGroupMember | Add-Member Noteproperty 'GroupOnPremID' $Group.OnPremisesSecurityIdentifier
            $AZGroupMember | Add-Member Noteproperty 'MemberName' $Member.DisplayName
            $AZGroupMember | Add-Member Noteproperty 'MemberID' $Member.ObjectID
            $AZGroupMember | Add-Member Noteproperty 'MemberType' $Member.ObjectType
            $AZGroupMember | Add-Member Noteproperty 'MemberOnPremID' $Member.OnPremisesSecurityIdentifier
            $Coll += $AZGroupMember#>

            $AZGroupMember = [PSCustomObject]@{
                GroupName = $Group.DisplayName
                GroupID = $GroupID
                GroupOnPremID = $Group.OnPremisesSecurityIdentifier
                MemberName = $Member.DisplayName
                MemberID = $Member.ObjectID
                MemberType = $Member.ObjectType
                MemberOnPremID = $Member.OnPremisesSecurityIdentifier
            }
            $Coll += $AZGroupMember
        }
    }
    New-Output -Coll $Coll -Type "groupmembers" -Directory $OutputDirectory
    
    # Inbound permissions against Virtual Machines
    # RoleDefinitionName            RoleDefinitionId
    # ------------------            ----------------
    # Contributor                   b24988ac-6180-42a0-ab88-20f7382dd24c
    # Owner                         8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator     18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    # Avere Contributor             4f8fab4f-1852-4a58-a46a-8eaf358af14a
    # Virtual Machine Contributor   9980e02c-c2be-4d73-94e8-173b1dc7cf3c
    $Coll = @()
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building VMs object for subscription ${SubDisplayName}"
    
        $AADVMs = Get-AzVm
        $TotalCount = $AADVMs.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building VMs object, processing ${TotalCount} VMs"
        } else {
            Write-Info "Done building VM object, processing ${TotalCount} VM"
        }
        $Progress = 0
        
        $AADVMs | ForEach-Object {

            $VM = $_
            $DisplayName = $VM.Name

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current VM: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current VM: ${DisplayName}"
                } 
            }
            
            $VMID = $VM.id
            $VMGuid = $VM.VmId
            
            $Roles = Get-AzRoleAssignment -scope $VMID
            
            ForEach ($Role in $Roles) {
            
                $ControllerType = $Role.ObjectType
                
                If ($ControllerType -eq "User") {
                    $Controller = Get-AzureADUser -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                
                If ($ControllerType -eq "Group") {
                    $Controller = Get-AzureADGroup -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
            
                $VMPrivilege = New-Object PSObject
                
                <#$VMPrivilege | Add-Member Noteproperty 'VMID' $VMGuid
                $VMPrivilege | Add-Member Noteproperty 'ControllerName' $Role.DisplayName
                $VMPrivilege | Add-Member Noteproperty 'ControllerID' $Role.ObjectID
                $VMPrivilege | Add-Member Noteproperty 'ControllerType' $Role.ObjectType
                $VMPrivilege | Add-Member Noteproperty 'ControllerOnPremID' $OnPremID
                $VMPrivilege | Add-Member Noteproperty 'RoleName' $Role.RoleDefinitionName
                $VMPrivilege | Add-Member Noteproperty 'RoleDefinitionId' $Role.RoleDefinitionId#>

                $VMPrivilege = [PSCustomObject]@{
                    VMID                = $VMGuid
                    ControllerName      = $Role.DisplayName
                    ControllerID        = $Role.ObjectID
                    ControllerType      = $Role.ObjectType
                    ControllerOnPremID  = $OnPremID
                    RoleName            = $Role.RoleDefinitionName
                    RoleDefinitionId    = $Role.RoleDefinitionId
                }
                
                $Coll += $VMPrivilege
            }
        }
    }
    New-Output -Coll $Coll -Type "vmpermissions" -Directory $OutputDirectory
    
    # Inbound permissions against resource group
    # RoleDefinitionName            RoleDefinitionId
    # ------------------            ----------------
    # Owner                         8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator     18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    $Coll = @()
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building resource groups object for subscription ${SubDisplayName}"
    
        $AADResourceGroups = Get-AzResourceGroup
        $TotalCount = $AADResourceGroups.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building resource groups object, processing ${TotalCount} resource groups"
        } else {
            Write-Info "Done building resource group object, processing ${TotalCount} resource group"
        }
        $Progress = 0
        
        $AADResourceGroups | ForEach-Object {

            $RG = $_
            $DisplayName = $RG.DisplayName

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
                } 
            }
            
            $RGID = $RG.ResourceId
            
            $Roles = Get-AzRoleAssignment -scope $RGID
            
            ForEach ($Role in $Roles) {
            
                $ControllerType = $Role.ObjectType
                
                If ($ControllerType -eq "User") {
                    $Controller = Get-AzureADUser -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                
                If ($ControllerType -eq "Group") {
                    $Controller = Get-AzureADGroup -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
            
                <#$RGPrivilege = New-Object PSObject
                $RGPrivilege | Add-Member Noteproperty 'RGID' $RGID
                $RGPrivilege | Add-Member Noteproperty 'ControllerName' $Role.DisplayName
                $RGPrivilege | Add-Member Noteproperty 'ControllerID' $Role.ObjectID
                $RGPrivilege | Add-Member Noteproperty 'ControllerType' $Role.ObjectType
                $RGPrivilege | Add-Member Noteproperty 'ControllerOnPremID' $OnPremID
                $RGPrivilege | Add-Member Noteproperty 'RoleName' $Role.RoleDefinitionName
                $RGPrivilege | Add-Member Noteproperty 'RoleDefinitionId' $Role.RoleDefinitionId#>

                $RGPrivilege = [PSCustomObject]@{
                    RGID = $RGID
                    ControllerName = $Role.DisplayName
                    ControllerID = $Role.ObjectID
                    ControllerType = $Role.ObjectType
                    ControllerOnPremID = $OnPremID
                    RoleName = $Role.RoleDefinitionName
                    RoleDefinitionId = $Role.RoleDefinitionId
                } 
                $Coll += $RGPrivilege
            }
        }
    }
    New-Output -Coll $Coll -Type "rgpermissions" -Directory $OutputDirectory
    
    # Inbound permissions against key vaults
    # RoleDefinitionName            RoleDefinitionId
    # ------------------            ----------------
    # Contributor                   b24988ac-6180-42a0-ab88-20f7382dd24c
    # Owner                         8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator     18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    # Key Vaults
    $Coll = @()
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building key vaults object for subscription ${SubDisplayName}"
    
        $AADKeyVaults = Get-AzKeyVault
        $TotalCount = $AADKeyVaults.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building key vaults object, processing ${TotalCount} key vaults"
        } else {
            Write-Info "Done building key vault object, processing ${TotalCount} key vault"
        }
        $Progress = 0

        $AADKeyVaults | ForEach-Object {

            $KeyVault = $_
            $DisplayName = $KeyVault.DisplayName

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
                } 
            }
            
            $KVID = $KeyVault.ResourceId
            
            $Roles = Get-AzRoleAssignment -scope $KVID
            
            ForEach ($Role in $Roles) {
            
                $ControllerType = $Role.ObjectType
                
                If ($ControllerType -eq "User") {
                    $Controller = Get-AzureADUser -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                
                If ($ControllerType -eq "Group") {
                    $Controller = Get-AzureADGroup -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
            
                <#$KVPrivilege = New-Object PSObject
                $KVPrivilege | Add-Member Noteproperty 'KVID' $KVID
                $KVPrivilege | Add-Member Noteproperty 'ControllerName' $Role.DisplayName
                $KVPrivilege | Add-Member Noteproperty 'ControllerID' $Role.ObjectID
                $KVPrivilege | Add-Member Noteproperty 'ControllerType' $Role.ObjectType
                $KVPrivilege | Add-Member Noteproperty 'ControllerOnPremID' $OnPremID
                $KVPrivilege | Add-Member Noteproperty 'RoleName' $Role.RoleDefinitionName
                $KVPrivilege | Add-Member Noteproperty 'RoleDefinitionId' $Role.RoleDefinitionId#>

                $KVPrivilege = [PSCustomObject]@{
                    KVID = $KVID
                    ControllerName = $Role.DisplayName
                    ControllerID = $Role.ObjectID
                    ControllerType = $Role.ObjectType
                    ControllerOnPremID = $OnPremID
                    RoleName = $Role.RoleDefinitionName
                    RoleDefinitionId = $Role.RoleDefinitionId
                }
                $Coll += $KVPrivilege
            }
        }
    }
    New-Output -Coll $Coll -Type "kvpermissions" -Directory $OutputDirectory
    
    <#$Coll = @()
    #KeyVault access policies
    $AADSubscriptions | ForEach-Object {

        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        
        Write-Info "Building key vaults object for subscription ${SubDisplayName}"
    
        $AADKeyVaults = Get-AzKeyVault
        $TotalCount = $AADKeyVaults.Count
        If ($TotalCount -gt 1) {
            Write-Info "Done building key vaults object, processing ${TotalCount} key vaults"
        } else {
            Write-Info "Done building key vault object, processing ${TotalCount} key vault"
        }
        $Progress = 0

        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        $AADKeyVaults | ForEach-Object {

            $KeyVault = $_
            $DisplayName = $KeyVault.DisplayName

            $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
                } 
            }

            $PrincipalMap = Get-PrincipalMap
            $KVID = $KeyVault.ResourceId
            
            $AccessPolicies = Get-AzKeyVault -VaultName $_.VaultName | select -expand accesspolicies
            
            ForEach ($Policy in $AccessPolicies) {
            
                $ObjectOnPremID = $PrincipalMap[$Policy.ObjectID]
            
                # Get Keys - PermissionsToKeys
                if ($Policy.PermissionsToKeys -Contains "Get") {
            
                    #$KVAccessPolicy = New-Object PSObject
                    #$KVAccessPolicy | Add-Member Noteproperty 'KVID' $KVID
                    #$KVAccessPolicy | Add-Member Noteproperty 'ControllerID' $Policy.ObjectID
                    #$KVAccessPolicy | Add-Member Noteproperty 'ObjectOnPremID' $ObjectOnPremID
                    #$KVAccessPolicy | Add-Member Noteproperty 'Access' "GetKeys"

                    $KVAccessPolicy = [PSCustomObject]@{
                        KVID            = $KVID
                        ControllerID    = $Policy.ObjectID
                        ObjectOnPremID  = $ObjectOnPremID
                        Access          = "GetKeys"
                    }
                
                    $Coll += $KVAccessPolicy
                    
                }
                # Get Certificates - PermissionsToCertificates
                if ($Policy.PermissionsToCertificates -Contains "Get") {
            
                    #$KVAccessPolicy = New-Object PSObject
                    #$KVAccessPolicy | Add-Member Noteproperty 'KVID' $KVID
                    #$KVAccessPolicy | Add-Member Noteproperty 'ControllerID' $Policy.ObjectID
                    #$KVAccessPolicy | Add-Member Noteproperty 'ObjectOnPremID' $ObjectOnPremID
                    #$KVAccessPolicy | Add-Member Noteproperty 'Access' "GetCertificates"

                    $KVAccessPolicy = [PSCustomObject]@{
                        KVID            = $KVID
                        ControllerID    = $Policy.ObjectID
                        ObjectOnPremID  = $ObjectOnPremID
                        Access          = "GetCertificates"
                    }
                
                    $Coll += $KVAccessPolicy
                    
                }
                # Get Secrets - PermissionsToSecrets
                if ($Policy.PermissionsToSecrets -Contains "Get") {
            
                    #$KVAccessPolicy = New-Object PSObject
                    #$KVAccessPolicy | Add-Member Noteproperty 'KVID' $KVID
                    #$KVAccessPolicy | Add-Member Noteproperty 'ControllerID' $Policy.ObjectID
                    #$KVAccessPolicy | Add-Member Noteproperty 'ObjectOnPremID' $ObjectOnPremID
                    #$KVAccessPolicy | Add-Member Noteproperty 'Access' "GetSecrets"

                    $KVAccessPolicy = [PSCustomObject]@{
                        KVID            = $KVID
                        ControllerID    = $Policy.ObjectID
                        ObjectOnPremID  = $ObjectOnPremID
                        Access          = "GetSecrets"
                    }
                    $Coll += $KVAccessPolicy
                    
                }
            }
        }
    }
    New-Output -Coll $Coll -Type "kvaccesspolicies" -Directory $OutputDirectory
    #>
    
    # Abusable AZ Admin Roles
    Write-Info "Beginning abusable Azure Admin role logic"
    Write-Info "Building initial admin role mapping object"
    $Results = Get-AzureADDirectoryRole | ForEach-Object {
        
        $Role = $_
        
        $RoleMembers = Get-AzureADDirectoryRoleMember -ObjectID $Role.ObjectID
        
        ForEach ($Member in $RoleMembers) {
        
            <#$RoleMembership = New-Object PSObject
            $RoleMembership | Add-Member Noteproperty 'MemberName' $Member.DisplayName
            $RoleMembership | Add-Member Noteproperty 'MemberID' $Member.ObjectID
            $RoleMembership | Add-Member Noteproperty 'MemberOnPremID' $Member.OnPremisesSecurityIdentifier
            $RoleMembership | Add-Member Noteproperty 'MemberUPN' $Member.UserPrincipalName
            $RoleMembership | Add-Member Noteproperty 'MemberType' $Member.ObjectType
            $RoleMembership | Add-Member Noteproperty 'RoleID' $Role.RoleTemplateId#>

            $RoleMembership = [PSCustomObject]@{
                MemberName      = $Member.DisplayName
                MemberID        = $Member.ObjectID
                MemberOnPremID  = $Member.OnPremisesSecurityIdentifier
                MemberUPN       = $Member.UserPrincipalName
                MemberType      = $Member.ObjectType
                RoleID          = $Role.RoleTemplateId
            }
        
            $RoleMembership
        
        }
        
    }
    Write-Info "Done building initial admin role mapping object"
    
    Write-Info "Massasing initial object into object we will use later"
    $UsersAndRoles = ForEach ($User in $Results) {
        $CurrentUser = $User.MemberID
		$CurrentObjectType = $User.MemberType
        $CurrentUserName = $User.MemberName
        $CurrentUserRoles = ($Results | ? { $_.MemberID -eq $CurrentUser }).RoleID
        $CurrentUserUPN = $User.MemberUPN
        $CurrentUserOnPremID = $User.MemberOnPremID
        
        <#$UserAndRoles = New-Object PSObject
        $UserAndRoles | Add-Member Noteproperty 'UserName' $CurrentUserName
        $UserAndRoles | Add-Member Noteproperty 'UserID' $CurrentUser
        $UserAndRoles | Add-Member Noteproperty 'UserOnPremID' $CurrentUserOnPremID
        $UserAndRoles | Add-Member Noteproperty 'UserUPN' $CurrentUserUPN
        $UserAndRoles | Add-Member Noteproperty 'RoleID' $CurrentUserRoles#>

        $UserAndRoles = [PSCustomObject]@{
            UserName        = $CurrentUserName
			ObjectType      = $CurrentObjectType
            UserID          = $CurrentUser
            UserOnPremID    = $CurrentUserOnPremID
            UserUPN         = $CurrentUserUPN
            RoleID          = $CurrentUserRoles
        }
        
        $UserAndRoles
    }

    $UserRoles = $UsersAndRoles | Sort-Object -Unique -Property UserName
    $UsersWithRoles = $UserRoles.UserID
    Write-Info "Done building object we will use later"

    Write-Info "Building our users without roles object"
    $UsersWithoutRoles = $AADUsers | ? { $_.ObjectID -NotIn $UsersWithRoles }
    Write-Info "Done building our users without roles object"
    
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
    Write-Info "Processing privileged authentication admin role"
    $PrivilegedAuthenticationAdmins = $UserRoles | ? { $_.RoleID -Contains '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' }
    $TotalCount = $PrivilegedAuthenticationAdmins.Count
    Write-Info "Privileged authentication admins to process: ${TotalCount}"
    $PrivilegedAuthenticationAdminRights = ForEach ($User in $PrivilegedAuthenticationAdmins) {
        $TargetUsers = $UserRoles | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        # Privileged authentication admins can reset ALL user passwords, including global admins
        # You can't reset passwords for external users, which have "#EXT#" added to their UPN
                
        ForEach ($TargetUser in $TargetUsers) {
                
            <#$PWResetRight = New-Object PSObject    
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserID
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremID#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
        }
            
        ForEach ($TargetUser in $UsersWithoutRoles) {
            
            <#$PWResetRight = New-Object PSObject    
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.DisplayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.ObjectId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.OnPremisesSecurityIdentifier#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }     
            $PWResetRight
        }
    }
    Write-Info "Done processing authentication admin role"
    
    # Authentication admins
    Write-Info "Processing authentication admin role"
    $AuthenticationAdmins = $UserRoles | ? { $_.RoleID -Contains 'c4e39bd9-1100-46d3-8c65-fb160da0071f' }
    $TotalCount = $AuthenticationAdmins.Count
    Write-Info "Authentication admins to process: ${TotalCount}"
    $AuthAdminsRights = ForEach ($User in $AuthenticationAdmins) {
            
        $TargetUsers = $UserRoles | ? { $AuthAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        # You can't reset passwords for external users, which have "#EXT#" added to their UPN
            
        ForEach ($TargetUser in $TargetUsers) {
            
            <#$PWResetRight = New-Object PSObject
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserID
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremID#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
            
            $PWResetRight
        }
        
        ForEach ($TargetUser in $UsersWithoutRoles) {
            
            <#$PWResetRight = New-Object PSObject
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.DisplayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.ObjectId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.OnPremisesSecurityIdentifier#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }
            
            $PWResetRight
        }
    }
    Write-Info "Done processing authentication admin role"
    
    # Help Desk Admin
    Write-Info "Processing help desk admin role"
    $HelpdeskAdmins = $UserRoles | ? { $_.RoleID -Contains '729827e3-9c14-49f7-bb1b-9608f156bbb8' }
    $TotalCount = $HelpdeskAdmins.Count
    Write-Info "Help desk admins to process: ${TotalCount}"
    $HelpdeskAdminsRights = ForEach ($User in $HelpdeskAdmins) {
            
        $TargetUsers = $UserRoles | ? { $HelpdeskAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
            
        ForEach ($TargetUser in $TargetUsers) {
            
            <#$PWResetRight = New-Object PSObject
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserID
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremID#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
            
            $PWResetRight
        }
        
        ForEach ($TargetUser in $UsersWithoutRoles) {
            
            <#$PWResetRight = New-Object PSObject
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.DisplayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.ObjectId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.OnPremisesSecurityIdentifier#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }
            
            $PWResetRight
        }
    
    }
    Write-Info "Done processing help desk admin role"
    
    # Password Admin role
    Write-Info "Processing password admin role"
    $PasswordAdmins = $UserRoles | ? { $_.RoleID -Contains '966707d0-3269-4727-9be2-8c3a10f19b9d' }
    $TotalCount = $PasswordAdmins.Count
    Write-Info "Password admins to process: ${TotalCount}"
    $PasswordAdminsRights = ForEach ($User in $PasswordAdmins) {
            
        $TargetUsers = $UserRoles | ? { $PasswordAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
            
        ForEach ($TargetUser in $TargetUsers) {
            
            <#$PWResetRight = New-Object PSObject  
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserID
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremID#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
            
            $PWResetRight
        }
        
        ForEach ($TargetUser in $UsersWithoutRoles) {
            
            <#$PWResetRight = New-Object PSObject
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.DisplayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.ObjectId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.OnPremisesSecurityIdentifier#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }
            
            $PWResetRight
        }

    }
    Write-Info "Done processing password admin role"
    
    # User Account Admin role
    Write-Info "Processing user account admin role"
    $UserAccountAdmins = $UserRoles | ? { $_.RoleID -Contains 'fe930be7-5e62-47db-91af-98c3a49a38b1' }
    $TotalCount = $UserAccountAdmins.Count
    Write-Info "User account admins to process: ${TotalCount}"
    $Progress = 0
    $UserAccountAdminsRights = ForEach ($User in $UserAccountAdmins) {

        $DisplayName = $User.UserName
        
        $Progress += 1
            $ProgressPercentage = ($Progress / $TotalCount) * 100

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing user account admins: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user account admin: ${DisplayName}"
            } else {
                Write-Info "Processing user account admins: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user account admin: ${DisplayName}" 
            }
            
        $TargetUsers = $UserRoles | ? { $UserAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
            
        ForEach ($TargetUser in $TargetUsers) {
            
            <#$PWResetRight = New-Object PSObject
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.UserName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.UserID
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.UserOnPremID#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
			
			$PWResetRight
        }

        $TargetUsers = $UsersWithoutRoles | ?{$_.OnPremisesSecurityIdentifier -eq $null} | ? { $_.UserUPN -NotMatch "#EXT#" }

        ForEach ($TargetUser in $TargetUsers) {

            <#$PWResetRight = New-Object PSObject
            
            $PWResetRight | Add-Member Noteproperty 'UserName' $User.UserName
            $PWResetRight | Add-Member Noteproperty 'UserID' $User.UserID
            $PWResetRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $PWResetRight | Add-Member Noteproperty 'TargetUserName' $TargetUser.DisplayName
            $PWResetRight | Add-Member Noteproperty 'TargetUserID' $TargetUser.ObjectId
            $PWResetRight | Add-Member Noteproperty 'TargetUserOnPremID' $TargetUser.OnPremisesSecurityIdentifier#>

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }

            $PWResetRight

        }   
    }
    Write-Info "Done processing user account admin role"
    
    $CloudGroups = $AADGroups | ? { $_.OnPremisesSecurityIdentifier -eq $null } | Select DisplayName, ObjectID
    
    # Intune administrator - 3a2c62db-5318-420d-8d74-23affee5d9d5 - Can add principals to cloud-resident security groups
    Write-Info "Processing Intune Admin role"
    $IntuneAdmins = $UserRoles | ? { $_.RoleID -Contains '3a2c62db-5318-420d-8d74-23affee5d9d5' }
    $IntuneAdminsRights = ForEach ($User in $IntuneAdmins) {
                
        ForEach ($TargetGroup in $CloudGroups) {
            
            <#$GroupRight = New-Object PSObject
            $GroupRight | Add-Member Noteproperty 'UserName' $User.UserName
            $GroupRight | Add-Member Noteproperty 'UserID' $User.UserID
            $GroupRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $GroupRight | Add-Member Noteproperty 'TargetGroupName' $TargetGroup.DisplayName
            $GroupRight | Add-Member Noteproperty 'TargetGroupID' $TargetGroup.ObjectID#>

            $GroupRight = [PSCustomObject]@{
                UserName        = $User.UserName
				ObjectType      = $User.ObjectType
                UserID          = $User.UserID
                UserOnPremID    = $User.UserOnPremID
                TargetGroupName = $TargetGroup.DisplayName
                TargetGroupID   = $TargetGroup.ObjectID
            }
            $GroupRight
        }
    }
    Write-Info "Done processing Intune Admin role"
    
    # Groups administrator - Can add principals to cloud-resident security groups
    Write-Info "Processing groups admin role"
    $GroupsAdmins = $UserRoles | ? { $_.RoleID -Contains 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
    $GroupsAdminsRights = ForEach ($User in $GroupsAdmins) {
                
        ForEach ($TargetGroup in $CloudGroups) {
            
            <#$GroupRight = New-Object PSObject
            $GroupRight | Add-Member Noteproperty 'UserName' $User.UserName
            $GroupRight | Add-Member Noteproperty 'UserID' $User.UserID
            $GroupRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
            $GroupRight | Add-Member Noteproperty 'TargetGroupName' $TargetGroup.DisplayName
            $GroupRight | Add-Member Noteproperty 'TargetGroupID' $TargetGroup.ObjectID#>

            $GroupRight = [PSCustomObject]@{
                UserName        = $User.UserName
				ObjectType      = $User.ObjectType
                UserID          = $User.UserID
                UserOnPremID    = $User.UserOnPremID
                TargetGroupName = $TargetGroup.DisplayName
                TargetGroupID   = $TargetGroup.ObjectID
            }
            $GroupRight
        }
    }
    Write-Info "Done processing groups admin role"
    
    # Rights against the tenant itself
    
    $TenantDetails = Get-AzureADTenantDetail
    
    # Global Admin - has full control of everything in the tenant
    
    Write-Info "Processing Global Admin role"
    $GlobalAdmins = $UserRoles | ? { $_.RoleID -Contains '62e90394-69f5-4237-9190-012177145e10' }
    $GlobalAdminsRights = ForEach ($User in $GlobalAdmins) {    
            
        <#$GlobalAdminRight = New-Object PSObject
        $GlobalAdminRight | Add-Member Noteproperty 'UserName' $User.UserName
        $GlobalAdminRight | Add-Member Noteproperty 'UserID' $User.UserID
        $GlobalAdminRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
        $GlobalAdminRight | Add-Member Noteproperty 'TenantDisplayName' $TenantDetails.DisplayName
        $GlobalAdminRight | Add-Member Noteproperty 'TenantID' $TenantDetails.ObjectID#>

        $GlobalAdminRight = [PSCustomObject]@{
            UserName            = $User.UserName
			ObjectType          = $User.ObjectType
            UserID              = $User.UserID
            UserOnPremID        = $User.UserOnPremID
            TenantDisplayName   = $TenantDetails.DisplayName
            TenantID            = $TenantDetails.ObjectID
        }
        $GlobalAdminRight
    }
    Write-Info "Done processing Global Admin role"
    
    # Privilege role administrator
    # Can add role assignments to any other user including themselves
    Write-Info "Processing Privileged Role Admin role"
    $PrivRoleColl = @()
    $PrivilegedRoleAdmins = $UserRoles | ? { $_.RoleID -Contains 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
    $PrivilegedRoleAdminRights = ForEach ($User in $PrivilegedRoleAdmins) { 
            
        <#$PrivilegedRoleAdminRight = New-Object PSObject
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'UserName' $User.UserName
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'UserID' $User.UserID
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'UserOnPremID' $User.UserOnPremID
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'TenantDisplayName' $TenantDetails.DisplayName
        $PrivilegedRoleAdminRight | Add-Member Noteproperty 'TenantID' $TenantDetails.ObjectID#>

        $PrivilegedRoleAdminRight = [PSCustomObject]@{
            UserName            = $User.UserName
			ObjectType          = $User.ObjectType
            UserID              = $User.UserID
            UserOnPremID        = $User.UserOnPremID
            TenantDisplayName   = $TenantDetails.DisplayName
            TenantID            = $TenantDetails.ObjectID
        }
        $PrivRoleColl += $PrivilegedRoleAdminRight
    }
    Write-Info "Done processing Privileged Role Admin role"
    
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
    New-Output -Coll $Coll -Type "pwresetrights" -Directory $OutputDirectory  

    $Coll = @()
    $IntuneAdminsRights | ForEach-Object {
        $Coll += $_
    }
    $GroupsAdminsRights | ForEach-Object {
        $Coll += $_
    }
    New-Output -Coll $Coll -Type "groupsrights" -Directory $OutputDirectory
    New-Output -Coll $GlobalAdminsRights -Type "globaladminrights" -Directory $OutputDirectory
    New-Output -Coll $PrivRoleColl -Type "privroleadminrights" -Directory $OutputDirectory

    $Coll = @()
    # Get app owners
    Get-AzureADApplication -All $True | ForEach-Object {

    $AppId = $_.AppId
    $ObjectId = $_.ObjectId
    $AppName = $_.DisplayName

    $AppOwners = Get-AzureADApplicationOwner -ObjectId $ObjectId
    
    ForEach ($Owner in $AppOwners) {
        
        <#$AzureAppOwner = New-Object PSObject        
        $AzureAppOwner | Add-Member Noteproperty 'AppId' $AppId
        $AzureAppOwner | Add-Member Noteproperty 'AppObjectId' $ObjectId
        $AzureAppOwner | Add-Member Noteproperty 'OwnerID' $Owner.ObjectId
        $AzureAppOwner | Add-Member Noteproperty 'OwnerType' $Owner.ObjectType
        $AzureAppOwner | Add-Member Noteproperty 'OwnerOnPremID' $Owner.OnPremisesSecurityIdentifier#>

        $AzureAppOwner = [PSCustomObject]@{
            AppId           = $AppId
            AppObjectId     = $ObjectId
            AppName         = $AppName
            OwnerID         = $Owner.ObjectId
            OwnerType       = $Owner.ObjectType
            OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
        }

        $Coll += $AzureAppOwner
    }
    }
    New-Output -Coll $Coll -Type "applicationowners" -Directory $OutputDirectory

   $Coll = @()
   $SPOS = Get-AzADApplication | Get-AzADServicePrincipal | %{
    
    <#$ServicePrincipals = New-Object PSObject
    $ServicePrincipals | Add-Member Noteproperty 'AppId' $_.ApplicationId
    $ServicePrincipals | Add-Member Noteproperty 'AppName' $_.DisplayName
    $ServicePrincipals | Add-Member Noteproperty 'ServicePrincipalId' $_.Id
    $ServicePrincipals | Add-Member Noteproperty 'ServicePrincipalType' $_.ObjectType#>

    $ServicePrincipals = [PSCustomObject]@{
        AppId                   = $_.ApplicationId
        AppName                 = $_.DisplayName
        ServicePrincipalId      = $_.Id
        ServicePrincipalType    = $_.ObjectType
    }

    $Coll += $ServicePrincipals

    }
    New-Output -Coll $Coll -Type "applicationtosp" -Directory $OutputDirectory
    
        
    $PrincipalRoles = ForEach ($User in $Results){
        $SPRoles = New-Object PSObject
        If ($User.MemberType -match 'servicePrincipal')
        {
         
        <#$SPRoles = New-Object PSObject
        $SPRoles | Add-Member NoteProperty 'RoleID' $User.RoleID
        $SPRoles | Add-Member NoteProperty 'SPId' $User.MemberID#>

        $SPRoles = [PSCustomObject]@{
            RoleID  = $User.RoleID
            SPId    = $User.MemberID
        }

        $SPRoles

        }
    }
   
    $SPswithoutRoles = $SPOS | Where-Object {$_.ServicePrincipalID -notin $PrincipalRoles.SPId}

    $Coll = @()
    # Application Admins - Can create new secrets for application service principals
    # Write to appadmins.json
    $AppAdmins = $UserRoles | Where-Object {$_.RoleID -match '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'}
    $SPsWithAzureAppAdminRole = $UserRoles | Where-Object {$_.RoleID -match '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' -and $_.UserType -match 'serviceprincipal' }
    $AppsWithAppAdminRole = ForEach ($SP in $SPsWithAzureAppAdminRole) {
        $AppWithRole = $SPOS | ?{$_.ServicePrincipalID -Match $SP.UserID}
        $AppWithRole
    }
    $AppAdminsRights = ForEach ($Principal in $AppAdmins) {
            
        $TargetApps = $AppsWithAppAdminRole
            
        ForEach ($TargetApp in $TargetApps) {
            
            <#$AppRight = New-Object PSObject
            $AppRight | Add-Member Noteproperty 'AppAdminID' $Principal.UserID
            $AppRight | Add-Member Noteproperty 'AppAdminType' $Principal.UserType
            $AppRight | Add-Member Noteproperty 'AppAdminOnPremID' $Principal.UserOnPremID
            $AppRight | Add-Member Noteproperty 'TargetAppID' $TargetApp.AppID#>

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $Coll += $AppRight
            
        }
        
        ForEach ($TargetApp in $SPswithoutRoles) {
            
            <#$AppRight = New-Object PSObject
            $AppRight | Add-Member Noteproperty 'AppAdminID' $Principal.UserID
            $AppRight | Add-Member Noteproperty 'AppAdminType' $Principal.UserType
            $AppRight | Add-Member Noteproperty 'AppAdminOnPremID' $Principal.UserOnPremID
            $AppRight | Add-Member Noteproperty 'TargetAppID' $TargetApp.AppId#>

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $Coll += $AppRight

        }
    }
    New-Output -Coll $Coll -Type "applicationadmins" -Directory $OutputDirectory
    
    
    # Cloud Application Admins - Can create new secrets for application service principals
    # Write to cloudappadmins.json
    $Coll = @()
    $CloudAppAdmins = $UserRoles | Where-Object {$_.RoleID -match '158c047a-c907-4556-b7ef-446551a6b5f7'}
    $SPsWithAzureAppAdminRole = $UserRoles | Where-Object {$_.RoleID -match '158c047a-c907-4556-b7ef-446551a6b5f7' -and $_.UserType -match 'serviceprincipal' }
    $AppsWithAppAdminRole = ForEach ($SP in $SPsWithAzureAppAdminRole) {
        $AppWithRole = $SPOS | ?{$_.ServicePrincipalID -Match $SP.UserID}
        $AppWithRole
    }
    $CloudAppAdminRights = ForEach ($Principal in $AppAdmins) {
            
        $TargetApps = $AppsWithAppAdminRole
            
        ForEach ($TargetApp in $TargetApps) {
            
            <#$AppRight = New-Object PSObject
            $AppRight | Add-Member Noteproperty 'AppAdminID' $Principal.UserID
            $AppRight | Add-Member Noteproperty 'AppAdminType' $Principal.UserType
            $AppRight | Add-Member Noteproperty 'AppAdminOnPremID' $Principal.UserOnPremID
            $AppRight | Add-Member Noteproperty 'TargetAppID' $TargetApp.AppID#>

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $Coll += $AppRight
            
        }
        
        ForEach ($TargetApp in $SPswithoutRoles) {
            
            <#$AppRight = New-Object PSObject
            $AppRight | Add-Member Noteproperty 'AppAdminID' $Principal.UserID
            $AppRight | Add-Member Noteproperty 'AppAdminType' $Principal.UserType
            $AppRight | Add-Member Noteproperty 'AppAdminOnPremID' $Principal.UserOnPremID
            $AppRight | Add-Member Noteproperty 'TargetAppID' $TargetApp.AppId#>

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $Coll += $AppRight
        }
    }
    New-Output -Coll $Coll -Type "cloudappadmins" -Directory $OutputDirectory

    Write-Host "Compressing files"
    $location = Get-Location
    If($OutputDirectory.path -eq $location.path){
        $name = $date + "-azurecollection"
        $jsonpath = $OutputDirectory.Path + '\' + "*.json"
        $destinationpath = $OutputDirectory.Path + '\' + "$name.zip"       
        Compress-Archive $jsonpath -DestinationPath $destinationpath
        rm $jsonpath
    }
    else{
        $name = $date + "-azurecollection"
        $jsonpath = $OutputDirectory + '\' + "*.json"
        $destinationpath = $OutputDirectory + '\' + "$name.zip"
        Compress-Archive $jsonpath -DestinationPath $destinationpath
        rm $jsonpath
    }
    Write-Host "Done! Drag and drop the zip into the BloodHound GUI to import data."
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
