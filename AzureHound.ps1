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
    If ($Verbose) {
        Write-Host $Message
    }
}

function New-Output($Coll, $Type, $Directory) {

    $Count = $Coll.Count

    Write-Host "Writing output for $($Type)"
	if ($null -eq $Coll) {
        $Coll = New-Object System.Collections.ArrayList
    }

    # ConvertTo-Json consumes too much memory on larger objects, which can have millions
    # of entries in a large tenant. Write out the JSON structure a bit at a time to work
    # around this. This is a bit inefficient, but makes this work when the tenant becomes
    # too large.
    $FileName = $Directory + [IO.Path]::DirectorySeparatorChar + $date + "-" + "az" + $($Type) + ".json"
    try {
        $Stream = [System.IO.StreamWriter]::new($FileName)

        # Write file header JSON
        $Stream.WriteLine('{')
        $Stream.WriteLine("`t""meta"": {")
        $Stream.WriteLine("`t`t""count"": $Count,")
        $Stream.WriteLine("`t`t""type"": ""az$($Type)"",")
        $Stream.WriteLine("`t`t""version"": 4")
        $Stream.WriteLine("`t},")        

        # Write data JSON
        $Stream.WriteLine("`t""data"": [")
        $Stream.Flush()

        $chunksize = 250
        $chunkarray = @()
        $parts = [math]::Ceiling($coll.Count / $chunksize)

        Write-Info "Chunking output in $chunksize item sections"
        for($n=0; $n -lt $parts; $n++){
            $start = $n * $chunksize
            $end = (($n+1)*$chunksize)-1
            $chunkarray += ,@($coll[$start..$end])
        }
        $Count = $chunkarray.Count

        $chunkcounter = 1
        $jsonout = ""
        ForEach ($chunk in $chunkarray) {
            Write-Info "Writing JSON chunk $chunkcounter/$Count"
            $jsonout = ConvertTo-Json($chunk)
            $jsonout = $jsonout.trimstart("[`r`n").trimend("`r`n]")
            $Stream.Write($jsonout)
            If ($chunkcounter -lt $Count) {
                $Stream.WriteLine(",")
            } Else {
                $Stream.WriteLine("")
            }
            $Stream.Flush()
            $chunkcounter += 1
        }
        $Stream.WriteLine("`t]")
        $Stream.WriteLine("}")
    } finally {
        $Stream.close()
    }
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
            Write-Host "Login via Az PS Module failed."
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

    $sect = 1 # for section counter on progress output
    $numsections = 40 # total number of sections

    # Enumerate users
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building users object, this may take a few minutes."; $sect++
	$AADUsers = Get-AzureADUser -All $True | Select UserPrincipalName,OnPremisesSecurityIdentifier,ObjectID,TenantId
    $TotalCount = $AADUsers.Count
    Write-Host "Done building users object, processing ${TotalCount} users"
    $Progress = 0
    $AADUsers | ForEach-Object {

        $User = $_
        $DisplayName = ($User.UserPrincipalName).Split('@')[0]

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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
        
        $null = $Coll.Add($CurrentUser)
    }
    New-Output -Coll $Coll -Type "users" -Directory $OutputDirectory

    # Enumerate groups
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building groups object, this may take a few minutes."; $sect++
    $AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    $TotalCount = $AADGroups.Count
    Write-Info "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.displayname

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        $CurrentGroup = [PSCustomObject]@{
            DisplayName                    =  $Group.displayname
            OnPremisesSecurityIdentifier   =  $Group.OnPremisesSecurityIdentifier
            ObjectID                       =  $Group.ObjectID
            TenantID                       =  $TenantID
        }
        
        $null = $Coll.Add($CurrentGroup)
    }
    New-Output -Coll $Coll -Type "groups" -Directory $OutputDirectory
    
    # Enumerate tenants:
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building tenant(s) object."; $sect++
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
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
            } 
        }

        $Current = [PSCustomObject]@{
            ObjectID    = $Tenant.ObjectId
            DisplayName = $Tenant.DisplayName
        }

        $null = $Coll.Add($Current)
    }
    New-Output -Coll $Coll -Type "tenants" -Directory $OutputDirectory

    # Enumerate subscriptions:
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building subscription(s) object."; $sect++
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
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
            } 
        }

        $Current = [PSCustomObject]@{
            Name            = $Subscription.Name
            SubscriptionId  = $Subscription.SubscriptionId
            TenantId        = $Subscription.TenantId
        }

        $null = $Coll.Add($Current)
    }
    New-Output -Coll $Coll -Type "subscriptions" -Directory $OutputDirectory
    
    # Enumerate resource groups:
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building resource groups object."; $sect++
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Info "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
                } 
            }
        
            $id = $RG.resourceid
            $resourceSub = "$id".split("/", 4)[2]

            $ResourceGroup = [PSCustomObject]@{
                ResourceGroupName   = $RG.ResourceGroupName
                SubscriptionID      = $resourceSub
                ResourceGroupID     = $RG.ResourceId
            }
        
            $null = $Coll.Add($ResourceGroup)
        }
    }

    New-Output -Coll $Coll -Type "resourcegroups" -Directory $OutputDirectory

    $Coll = New-Object System.Collections.ArrayList
    # Get VMs
    Write-Info "== [$sect/$numsections] Building virtual machines object."; $sect++
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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

            $AzVM = [PSCustomObject]@{
                AzVMName = $VM.Name
                AZID = $VM.VmId
                ResourceGroupName = $RGName
                ResoucreGroupSub = $resourceSub
                ResourceGroupID = $RGID
            }

            $null = $Coll.Add($AzVM)
        
        }
    }
    New-Output -Coll $Coll -Type "vms" -Directory $OutputDirectory
    
    $Coll = New-Object System.Collections.ArrayList
    # Get KeyVaults
    Write-Info "== [$sect/$numsections] Building keyvaults object."; $sect++
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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

            $AzKeyVault = [PSCustomObject]@{
                AzKeyVaultName      = $KeyVault.VaultName
                AzKeyVaultID        = $KeyVault.ResourceId
                ResourceGroupName   = $RGName
                ResoucreGroupSub    = $resourceSub
                ResourceGroupID     = $RGID
            }
        
            $null = $Coll.Add($AzKeyVault)
        }
    }
    New-Output -Coll $Coll -Type "keyvaults" -Directory $OutputDirectory
    
    $Coll = New-Object System.Collections.ArrayList
    # Get devices and their owners
    Write-Info "== [$sect/$numsections] Building devices object."; $sect++
    $AADDevices =  Get-AzureADDevice | ?{$_.DeviceOSType -Match "Windows" -Or $_.DeviceOSType -Match "Mac"}
    $TotalCount = $AADDevices.Count
    Write-Info "Done building devices object, processing ${TotalCount} devices"
    $Progress = 0
    $AADDevices | ForEach-Object {

        $Device = $_
        $DisplayName = $Device.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
            } 
        }
        
        $Owner = Get-AzureADDeviceRegisteredOwner -ObjectID $Device.ObjectID

        $AzureDeviceOwner = [PSCustomObject]@{
            DeviceDisplayname   = $Device.Displayname
            DeviceID            = $Device.ObjectID
            DeviceOS            = $Device.DeviceOSType
            OwnerDisplayName    = $Owner.Displayname
            OwnerID             = $Owner.ObjectID
            OwnerType           = $Owner.ObjectType
            OwnerOnPremID       = $Owner.OnPremisesSecurityIdentifier
        }

        $null = $Coll.Add($AzureDeviceOwner)
    }
    New-Output -Coll $Coll -Type "devices" -Directory $OutputDirectory
    
    # Enumerate group owners
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building group owners object."; $sect++
    Write-Info "Checking if groups object is already built..."
    If ($AADGroups.Count -eq 0) {
        Write-Info "Creating groups object, this may take a few minutes."
        $AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    }
    $TargetGroups = $AADGroups | ?{$_.OnPremisesSecurityIdentifier -eq $null}
    $TotalCount = $TargetGroups.Count
    Write-Info "Done building target groups object, processing ${TotalCount} groups"
    $Progress = 0
    $TargetGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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

            $AZGroupOwner = [PSCustomObject]@{
                GroupName       = $Group.DisplayName
                GroupID         = $GroupID
                OwnerName       = $Owner.DisplayName
                OwnerID         = $Owner.ObjectID
                OwnerType       = $Owner.ObjectType
                OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
            }
            $null = $Coll.Add($AZGroupOwner)   
        }   
    }
    New-Output -Coll $Coll -Type "groupowners" -Directory $OutputDirectory

    # Enumerate group members
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building group members object."; $sect++
    Write-Info "Checking if groups object is already built..."
    If ($AADGroups.Count -eq 0) {
        Write-Info "Creating groups object, this may take a few minutes."
        $AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    }
    $TotalCount = $AADGroups.Count
    Write-Info "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $AADGroups | ForEach-Object {

        $Group = $_
        $DisplayName = $Group.DisplayName

        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Info "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Info "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }

        $GroupID = $_.ObjectID
        $Members = Get-AzureADGroupMember -All $True -ObjectId "$GroupID"
        
        ForEach ($Member in $Members) {

            $AZGroupMember = [PSCustomObject]@{
                GroupName = $Group.DisplayName
                GroupID = $GroupID
                GroupOnPremID = $Group.OnPremisesSecurityIdentifier
                MemberName = $Member.DisplayName
                MemberID = $Member.ObjectID
                MemberType = $Member.ObjectType
                MemberOnPremID = $Member.OnPremisesSecurityIdentifier
            }
            $null = $Coll.Add($AZGroupMember)
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
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building virtual machine permissions object."; $sect++
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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
				
				If ($ControllerType -eq "ServicePrincipal") {
                    $Controller = Get-AzureADServicePrincipal -ObjectID $Role.ObjectID
                    $OnPremID = $null
                }
            
                $VMPrivilege = New-Object PSObject

                $VMPrivilege = [PSCustomObject]@{
                    VMID                = $VMGuid
                    ControllerName      = $Role.DisplayName
                    ControllerID        = $Role.ObjectID
                    ControllerType      = $Role.ObjectType
                    ControllerOnPremID  = $OnPremID
                    RoleName            = $Role.RoleDefinitionName
                    RoleDefinitionId    = $Role.RoleDefinitionId
                }
                
                $null = $Coll.Add($VMPrivilege)
            }
        }
    }
    New-Output -Coll $Coll -Type "vmpermissions" -Directory $OutputDirectory
    
    # Inbound permissions against resource group
    # RoleDefinitionName            RoleDefinitionId
    # ------------------            ----------------
    # Owner                         8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    # User Access Administrator     18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building resource group permissions object."; $sect++
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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

                $RGPrivilege = [PSCustomObject]@{
                    RGID = $RGID
                    ControllerName = $Role.DisplayName
                    ControllerID = $Role.ObjectID
                    ControllerType = $Role.ObjectType
                    ControllerOnPremID = $OnPremID
                    RoleName = $Role.RoleDefinitionName
                    RoleDefinitionId = $Role.RoleDefinitionId
                } 
                $null = $Coll.Add($RGPrivilege)
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
    $Coll = New-Object System.Collections.ArrayList
    Write-Info "== [$sect/$numsections] Building key vault permissions object."; $sect++
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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

                $KVPrivilege = [PSCustomObject]@{
                    KVID = $KVID
                    ControllerName = $Role.DisplayName
                    ControllerID = $Role.ObjectID
                    ControllerType = $Role.ObjectType
                    ControllerOnPremID = $OnPremID
                    RoleName = $Role.RoleDefinitionName
                    RoleDefinitionId = $Role.RoleDefinitionId
                }
                $null = $Coll.Add($KVPrivilege)
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
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

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
    Write-Info "== [$sect/$numsections] Building initial admin role mapping object."; $sect++
    $Results = Get-AzureADDirectoryRole | ForEach-Object {
        
        $Role = $_
        
        $RoleMembers = Get-AzureADDirectoryRoleMember -ObjectID $Role.ObjectID
        
        ForEach ($Member in $RoleMembers) {

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
    
    Write-Info "== [$sect/$numsections] Massaging initial admin object into an object to be used later."; $sect++
    $UsersAndRoles = ForEach ($User in $Results) {
        $CurrentUser = $User.MemberID
		$CurrentObjectType = $User.MemberType
        $CurrentUserName = $User.MemberName
        $CurrentUserRoles = ($Results | ? { $_.MemberID -eq $CurrentUser }).RoleID
        $CurrentUserUPN = $User.MemberUPN
        $CurrentUserOnPremID = $User.MemberOnPremID

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

    Write-Info "== [$sect/$numsections] Building users without roles object"; $sect++
    $UsersWithoutRoles = $AADUsers | ? { $_.ObjectID -NotIn $UsersWithRoles }
    
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
    Write-Info "== [$sect/$numsections] Processing privileged authentication admin role."; $sect++
    $PrivilegedAuthenticationAdmins = $UserRoles | ? { $_.RoleID -Contains '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' }
    $TotalCount = $PrivilegedAuthenticationAdmins.Count
    Write-Info "Privileged authentication admins to process: ${TotalCount}"
    $PrivilegedAuthenticationAdminRights = ForEach ($User in $PrivilegedAuthenticationAdmins) {
        $TargetUsers = $UserRoles | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        # Privileged authentication admins can reset ALL user passwords, including global admins
        # You can't reset passwords for external users, which have "#EXT#" added to their UPN
                
        ForEach ($TargetUser in $TargetUsers) {

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
    
    # Authentication admins
    Write-Info "== [$sect/$numsections] Processing authentication admin role"; $sect++
    $AuthenticationAdmins = $UserRoles | ? { $_.RoleID -Contains 'c4e39bd9-1100-46d3-8c65-fb160da0071f' }
    $TotalCount = $AuthenticationAdmins.Count
    Write-Info "Authentication admins to process: ${TotalCount}"
    $AuthAdminsRights = ForEach ($User in $AuthenticationAdmins) {
            
        $TargetUsers = $UserRoles | ? { $AuthAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        # You can't reset passwords for external users, which have "#EXT#" added to their UPN
            
        ForEach ($TargetUser in $TargetUsers) {

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
    
    # Help Desk Admin
    Write-Info "== [$sect/$numsections] Processing help desk admin role"; $sect++
    $HelpdeskAdmins = $UserRoles | ? { $_.RoleID -Contains '729827e3-9c14-49f7-bb1b-9608f156bbb8' }
    $TotalCount = $HelpdeskAdmins.Count
    Write-Info "Help desk admins to process: ${TotalCount}"
    $HelpdeskAdminsRights = ForEach ($User in $HelpdeskAdmins) {
            
        $TargetUsers = $UserRoles | ? { $HelpdeskAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
            
        ForEach ($TargetUser in $TargetUsers) {

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
    
    # Password Admin role
    Write-Info "== [$sect/$numsections] Processing password admin role"; $sect++
    $PasswordAdmins = $UserRoles | ? { $_.RoleID -Contains '966707d0-3269-4727-9be2-8c3a10f19b9d' }
    $TotalCount = $PasswordAdmins.Count
    Write-Info "Password admins to process: ${TotalCount}"
    $PasswordAdminsRights = ForEach ($User in $PasswordAdmins) {
            
        $TargetUsers = $UserRoles | ? { $PasswordAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
            
        ForEach ($TargetUser in $TargetUsers) {

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
    
    # User Account Admin role
    Write-Info "== [$sect/$numsections] Processing user account admin role"; $sect++
    $UserAccountAdmins = $UserRoles | ? { $_.RoleID -Contains 'fe930be7-5e62-47db-91af-98c3a49a38b1' }
    $TotalCount = $UserAccountAdmins.Count
    Write-Info "User account admins to process: ${TotalCount}"
    $Progress = 0
    $UserAccountAdminsRights = ForEach ($User in $UserAccountAdmins) {

        $DisplayName = $User.UserName
        
        $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

            If ($Progress -eq $TotalCount) {
                Write-Info "Processing user account admins: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user account admin: ${DisplayName}"
            } else {
                Write-Info "Processing user account admins: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user account admin: ${DisplayName}" 
            }
            
        $TargetUsers = $UserRoles | ? { $UserAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
            
        ForEach ($TargetUser in $TargetUsers) {

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
    
    $CloudGroups = $AADGroups | ? { $_.OnPremisesSecurityIdentifier -eq $null } | Select DisplayName, ObjectID
    
    # Intune administrator - 3a2c62db-5318-420d-8d74-23affee5d9d5 - Can add principals to cloud-resident security groups
    Write-Info "== [$sect/$numsections] Processing Intune Admin role"; $sect++
    $IntuneAdmins = $UserRoles | ? { $_.RoleID -Contains '3a2c62db-5318-420d-8d74-23affee5d9d5' }
    $IntuneAdminsRights = ForEach ($User in $IntuneAdmins) {
                
        ForEach ($TargetGroup in $CloudGroups) {

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
    
    # Groups administrator - Can add principals to cloud-resident security groups
    Write-Info "== [$sect/$numsections] Processing groups admin role"; $sect++
    $GroupsAdmins = $UserRoles | ? { $_.RoleID -Contains 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
    $GroupsAdminsRights = ForEach ($User in $GroupsAdmins) {
                
        ForEach ($TargetGroup in $CloudGroups) {

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
    
    # Rights against the tenant itself
    Write-Info "== [$sect/$numsections] Getting tenant details"; $sect++
    $TenantDetails = Get-AzureADTenantDetail
    
    # Global Admin - has full control of everything in the tenant
    
    Write-Info "== [$sect/$numsections] Processing Global Admin role"; $sect++
    $GlobalAdmins = $UserRoles | ? { $_.RoleID -Contains '62e90394-69f5-4237-9190-012177145e10' }
    $GlobalAdminsRights = ForEach ($User in $GlobalAdmins) {    

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
    
    # Privilege role administrator
    # Can add role assignments to any other user including themselves
    Write-Info "== [$sect/$numsections] Processing Privileged Role Admin role"; $sect++
    $PrivRoleColl = New-Object System.Collections.ArrayList
    $PrivilegedRoleAdmins = $UserRoles | ? { $_.RoleID -Contains 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
    $PrivilegedRoleAdminRights = ForEach ($User in $PrivilegedRoleAdmins) { 

        $PrivilegedRoleAdminRight = [PSCustomObject]@{
            UserName            = $User.UserName
			ObjectType          = $User.ObjectType
            UserID              = $User.UserID
            UserOnPremID        = $User.UserOnPremID
            TenantDisplayName   = $TenantDetails.DisplayName
            TenantID            = $TenantDetails.ObjectID
        }
        $null = $PrivRoleColl.Add($PrivilegedRoleAdminRight)
    }
    
    Write-Info "== [$sect/$numsections] Collating privileged admin rights"; $sect++
    $Coll = New-Object System.Collections.ArrayList
    $PrivilegedAuthenticationAdminRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    Write-Info "== [$sect/$numsections] Collating authentication admin rights"; $sect++
    $AuthAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    Write-Info "== [$sect/$numsections] Collating helpdesk admin rights"; $sect++
    $HelpdeskAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    Write-Info "== [$sect/$numsections] Collating password admin rights"; $sect++
    $PasswordAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    Write-Info "== [$sect/$numsections] Collating user account admin rights"; $sect++
    $UserAccountAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    New-Output -Coll $Coll -Type "pwresetrights" -Directory $OutputDirectory  

    Write-Info "== [$sect/$numsections] Collating In-Tune admin rights"; $sect++
    $Coll = New-Object System.Collections.ArrayList
    $IntuneAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    Write-Info "== [$sect/$numsections] Collating groups admin rights"; $sect++
    $GroupsAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    Write-Info "== [$sect/$numsections] Outputting rights"; $sect++
    New-Output -Coll $Coll -Type "groupsrights" -Directory $OutputDirectory
    New-Output -Coll $GlobalAdminsRights -Type "globaladminrights" -Directory $OutputDirectory
    New-Output -Coll $PrivRoleColl -Type "privroleadminrights" -Directory $OutputDirectory

    $Coll = New-Object System.Collections.ArrayList
    # Get app owners
	Write-Info "== [$sect/$numsections] Processing application owners"; $sect++
    Get-AzureADApplication -All $True | ForEach-Object {

    $AppId = $_.AppId
    $ObjectId = $_.ObjectId
    $AppName = $_.DisplayName

    $AppOwners = Get-AzureADApplicationOwner -ObjectId $ObjectId
    
    ForEach ($Owner in $AppOwners) {

        $AzureAppOwner = [PSCustomObject]@{
            AppId           = $AppId
            AppObjectId     = $ObjectId
            AppName         = $AppName
            OwnerID         = $Owner.ObjectId
            OwnerType       = $Owner.ObjectType
            OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
        }

        $null = $Coll.Add($AzureAppOwner)
    }
    }
    New-Output -Coll $Coll -Type "applicationowners" -Directory $OutputDirectory

   $Coll = New-Object System.Collections.ArrayList
   Write-Info "== [$sect/$numsections] Processing application to service principal relations"; $sect++
   $SPOS = Get-AzADApplication | Get-AzADServicePrincipal | %{

    $ServicePrincipals = [PSCustomObject]@{
        AppId                   = $_.ApplicationId
        AppName                 = $_.DisplayName
        ServicePrincipalId      = $_.Id
        ServicePrincipalType    = $_.ObjectType
    }

    $null = $Coll.Add($ServicePrincipals)

    }
    New-Output -Coll $Coll -Type "applicationtosp" -Directory $OutputDirectory
        
    Write-Info "== [$sect/$numsections] Getting principals for each admin role"; $sect++
    $PrincipalRoles = ForEach ($User in $Results){
        $SPRoles = New-Object PSObject
        If ($User.MemberType -match 'servicePrincipal')
        {

        $SPRoles = [PSCustomObject]@{
            RoleID  = $User.RoleID
            SPId    = $User.MemberID
        }

        $SPRoles

        }
    }
   
    $SPswithoutRoles = $SPOS | Where-Object {$_.ServicePrincipalID -notin $PrincipalRoles.SPId}

    $Coll = New-Object System.Collections.ArrayList
	Write-Info "== [$sect/$numsections] Processing Application Admins"; $sect++
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

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $null = $Coll.Add($AppRight)
            
        }
        
        ForEach ($TargetApp in $SPswithoutRoles) {

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $null = $Coll.Add($AppRight)

        }
    }
    New-Output -Coll $Coll -Type "applicationadmins" -Directory $OutputDirectory
    
    # Cloud Application Admins - Can create new secrets for application service principals
    # Write to cloudappadmins.json
	Write-Info "== [$sect/$numsections] Processing Cloud Application Admins"; $sect++
    $Coll = New-Object System.Collections.ArrayList
    $CloudAppAdmins = $UserRoles | Where-Object {$_.RoleID -match '158c047a-c907-4556-b7ef-446551a6b5f7'}
    $SPsWithAzureAppAdminRole = $UserRoles | Where-Object {$_.RoleID -match '158c047a-c907-4556-b7ef-446551a6b5f7' -and $_.UserType -match 'serviceprincipal' }
    $AppsWithAppAdminRole = ForEach ($SP in $SPsWithAzureAppAdminRole) {
        $AppWithRole = $SPOS | ?{$_.ServicePrincipalID -Match $SP.UserID}
        $AppWithRole
    }
    $CloudAppAdminRights = ForEach ($Principal in $AppAdmins) {
            
        $TargetApps = $AppsWithAppAdminRole
            
        ForEach ($TargetApp in $TargetApps) {

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $null = $Coll.Add($AppRight)
            
        }
        
        ForEach ($TargetApp in $SPswithoutRoles) {

            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            
            $null = $Coll.Add($AppRight)
        }
    }
    New-Output -Coll $Coll -Type "cloudappadmins" -Directory $OutputDirectory

    Write-Host "== [$sect/$numsections] Compressing files"; $sect++
    $location = Get-Location
    $name = $date + "-azurecollection"
    If($OutputDirectory.path -eq $location.path){
        $jsonpath = $OutputDirectory.Path + [IO.Path]::DirectorySeparatorChar + "$date-*.json"
        $destinationpath = $OutputDirectory.Path + [IO.Path]::DirectorySeparatorChar + "$name.zip"
    }
    else{
        $jsonpath = $OutputDirectory + [IO.Path]::DirectorySeparatorChar + "$date-*.json"
        $destinationpath = $OutputDirectory + [IO.Path]::DirectorySeparatorChar + "$name.zip"
    }

    $error.Clear()
    try {
        Compress-Archive $jsonpath -DestinationPath $destinationpath
    }
    catch {
        Write-Host "Zip file creation failed, JSON files may still be importable."
    }
    if (!$error) {
        Write-Host "Zip file created: $destinationpath"
        rm $jsonpath
        Write-Host "Done! Drag and drop the zip into the BloodHound GUI to import data."
    }
}
