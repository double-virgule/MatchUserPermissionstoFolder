############################
Function Get-ADUserNestedGroups { #This function gets ALL groups a user is a member of, through all chains, and displays it as one lump result
# Taken from http://blog.tofte-it.dk/powershell-get-all-nested-groups-for-a-user-in-active-directory/
    Param
    (
        [string]$DistinguishedName,
        [array]$Groups = @()
    )
 
    #Get the AD object, and get group membership.
    $ADObject = Get-ADObject -Filter "DistinguishedName -eq '$DistinguishedName'" -Properties memberOf, DistinguishedName;
    
    
    #If object exists.
    If ($ADObject) {
        #Enumurate through each of the groups.
        Foreach ($GroupDistinguishedName in $ADObject.memberOf) {
            #Get member of groups from the enummerated group.
            $CurrentGroup = Get-ADObject -Filter "DistinguishedName -eq '$GroupDistinguishedName'" -Properties memberOf, DistinguishedName;
       
            #Check if the group is already in the array.
            If (($Groups | Where-Object { $_.DistinguishedName -eq $GroupDistinguishedName }).Count -eq 0) {
                #Add group to array.
                $Groups += $CurrentGroup;
 
                #Get recursive groups.      
                $Groups = Get-ADUserNestedGroups -DistinguishedName $GroupDistinguishedName -Groups $Groups;
            }
        }
    }
     

    #Return groups.
    Return $Groups;
}
################# 
     function getgroupchain { #This function gets all groups a user is a member of and builds a chain of access
    
            Param
            (
                [array]$g2c = @(),
                [array]$gc = @(),
                [array]$staticgroups = @(),
                [array]$anyusergroup = @()
            )

            foreach ($mog in $g2c) {
                if ($mog -in $staticgroups) {
                    #if group is in list of groups that is directly applied to user...
                    $gc += $mog # add it to the chain of groups and exit

                }
                elseif ($mog -in $anyusergroup) {
                    # if it's in the full list      
                    $gc += $mog # add it to the chain of groups and continue

                    $nextlevel = Get-ADGroupMember -Identity $mog | ? { $_.objectclass -eq "group" }
                    if ($nextlevel -ne $null) {
                        $gc += getgroupchain -g2c $nextlevel.name -staticgroups $staticgroups -anyusergroup $anyusergroup #and run function again.
                    }
                }
    
            }Return $gc
        }
#####

$logfile = "C:\Users\$env:UserName\desktop\UserGrouptoACLTracking.txt"

$user = Read-Host "What is the user that has access to the folder?" 

Write-Output $user | Out-file $logfile  -append #logging

$newpath = Read-Host "What is the folder the user has access to? (Full UNC Path if Network Folder)" 

$folderstatus = Test-path -path $newpath

Write-Output "Full folder path: $newpath"  | Out-file $logfile -append #logging

#### Path Check ####

do {
    if ($folderstatus -eq $false) { 
        Write-Output "That folder is not valid. Please try again."
        $newpath = Read-Host "What is the folder the user has access to? (full path! \\domain\share\etc) " 
        $folderstatus = Test-path -path $newpath
    }
    else {
        Write-Output "Folder $newpath is valid."
        $folderstatus -eq $true
    }

} while ($folderstatus -eq $false) 

#### END Path Check 

$groupsonfolder = Get-Acl -Path $newpath #gets all groups on folder
Write-Output " " | Out-file $logfile -Append #logging
Write-output "Groups on folder:"  | Out-file $logfile -Append #logging
Write-Output $groupsonfolder.Access.identityreference  | Out-file $logfile -Append #logging
Write-Output " "  | Out-file $logfile -Append #logging
Write-Output "Filtered to AD groups:" | Out-file $logfile -Append #logging

$filtered_groupsonfolder = @() #New array 

#buildarray
foreach ($gu in $groupsonfolder) {

$filtered_groupsonfolder += $gu.Access.identityreference.value

}

Write-output "Checking user..."  | Tee-Object $logfile -Append

#### Test User Function ### Verifies username is correct

$Test_User = Get-ADUser -Filter { samAccountName -eq $user } 

while ($Test_User -eq $null) {
    #if samaccountname doesn't exist...
    Write-Host "User does not exist in AD. Please try again." 

    $nearby_users = $user.SubString(0, 1) + "*" #...get first letter of user's name...
    Write-Host "Possible matches: `n" 
    Get-ADUser -Filter 'Name -like $nearby_users' | Sort-Object | FT name, SamAccountName -AutoSize #..and list nearby users

    $user = Read-Host "What is the user's name (First_Last)"
    $Test_User = Get-ADUser -Filter { sAMAccountName -eq $user } 
} 

####

$u_distinguishedname = Get-AdUser -Identity $user -Properties distinguishedname
#The user to check.
$Usertocheck = $u_distinguishedname.DistinguishedName #changes username to distinguishedname for Get-ADObject
 
# runs Get-ADUserNestedGroups function to pull ALL groups as one block
$Groups = Get-ADUserNestedGroups -DistinguishedName $usertocheck | select name

$nodomainusers = Get-ADPrincipalGroupMembership -Identity $user | ? {$_.name -like "Domain Users"}
if ($nodomainusers -ne $null) { 
$Groups += Get-AdObject -filter "DistinguishedName -eq 'CN=Domain Users,CN=Builtin,DC=<DOMAIN>,DC=<DOMAIN>'" | ? {$_.name -eq "Domain Users"} ## Fill in your DC variables here
$Groups += Get-ADUserNestedGroups -DistinguishedName 'CN=Domain Users,CN=Builtin,DC=<DOMAIN>,DC=<DOMAIN>'
}
 

Write-output "All user $user's groups: "  | Out-file $logfile -Append

$Groups | Select-Object Name | Sort-Object -Property Name | Out-file $logfile -Append #logging

Write-Output "User is a member of $($groups.Count) groups."  | tee-object $logfile -Append #shows number of groups user is a member of
c
#########################################


Write-Output "Comparing Access..." | Tee-object $logfile -Append

#### All Matched Groups ### Gets all groups that are both attached to User's account and on the folder ###

$filtered_groupsonfolder = $filtered_groupsonfolder -replace '^.*\\', '' #removes domain\ from ACL groups
$matchedgroups = @() #makes new array
foreach ($ug in $groups) {
    
    if ($filtered_groupsonfolder -contains $ug.name) {

        $matchedgroups += $ug.name

    }
    else { 

        "User group $($ug.name) is not on $newpath." | Out-File $logfile -Append #logging

    }
}
if ($matchedgroups -ne $null) { 
Write-Output "$user has permissions to $newpath by:" $matchedgroups}  #first real output - All groups that provide access to the folder that the user
    else {Write-Output "-----------"
    Write-Output "$user has no access to that folder." | Tee-Object $logfile -append}
                                                                    #has access to, but as a block - Chaining happens below

### Backward Trace #### Builds access path for all groups that connect user to folder

$staticgroups = Get-ADPrincipalGroupMembership -Identity $user #get all user groups

foreach ($mg in $matchedgroups) { #for each group that is in both the user's groups somewhere in the chain, and on the folder's ACL

    $grouptocheck = [string]$mg #convert group to string
    $memberofgroups = Get-ADPrincipalGroupMembership -Identity $grouptocheck #all groups primary group is member of

        $groupchain = @()
        $groupchain = getgroupchain -g2c $mg -staticgroups $staticgroups.name -anyusergroup $groups.name
        # Queues up GetGroupChain function - 
        # G2C = the group that the user is a member of and is on the folder's ACL
        # staticgroups = All groups that are directly applied to the user's account - No chained groups
        # anyusergroup = All groups that touch the user's account - including all chained groups

$groupstring = "$newpath" #builds the chain string, folder path first

foreach ($gce in $groupchain) { # foreach member of the groupchain string that getgroupchain outputs

   $groupstring += " <- $gce" #add it to the string

}

$groupstring += " <- $user"


# Final Output

Write-output "----------------" 
Write-Output "USER: $user" | Tee-Object $logfile -append 
Write-Output "has permissions to FOLDER: $newpath" | Tee-Object $logfile -append 
Write-Output "with GROUP: $mg" | Tee-Object $logfile -append 
Write-Output "through the following CHAIN:" | Tee-Object $logfile -append 
Write-Output $groupstring | Tee-Object $logfile -append 

#and loop if necessary

}
