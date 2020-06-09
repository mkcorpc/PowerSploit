function Has-WritePermissionToExeFile($Path, $User) { 
    $Nodes = (Get-ChildItem -Filter "*.exe" -Recurse $Path).FullName 
    ForEach ($Node in $Nodes) { 
        $Rights = (get-acl $Node).Access 
        ForEach ($Right in $Rights) { 
           if ($Right.IdentityReference.toString() -eq $User -or $Right.IdentityReference.toString() -eq "NT AUTHORITY\Authenticated Users") 
                { 
                        if ($Right.FileSystemRights.toString() -eq "FullControl" -or $Right.FileSystemRights.toString().contains("Modify")) 
                        { 
                                Write-Host "Write access detected for " $Node 
                            } 
                } 
            } 
    } 
} 

function Has-WritePermissionToDllFile($Path, $User) { 
    $Nodes = (Get-ChildItem -Filter "*.exe" -Recurse $Path).FullName 
    ForEach ($Node in $Nodes) { 
        $Rights = (get-acl $Node).Access 
        ForEach ($Right in $Rights) { 
           if ($Right.IdentityReference.toString() -eq $User -or $Right.IdentityReference.toString() -eq "NT AUTHORITY\Authenticated Users") 
                { 
                        if ($Right.FileSystemRights.toString() -eq "FullControl" -or $Right.FileSystemRights.toString().contains("Modify")) 
                        { 
                                Write-Host "Write access detected for " $Node 
                            } 
                } 
            } 
    } 
} 

function Has-WritePermissionToDir($Path, $User) { 
    $Nodes = (Get-ChildItem -Directory -Recurse $Path).FullName 
    ForEach ($Node in $Nodes) { 
        $Rights = (get-acl $Node).Access 
        ForEach ($Right in $Rights) 
        { 
                if ($Rights.IdentityReference.toString() -eq $User -or $Rights.IdentityReference.toString() -eq "NT AUTHORITY\Authenticated Users") 
                { 
                        if ($Right.FileSystemRights.toString() -eq "FullControl" -or $Right.FileSystemRights.toString().contains("Modify")) 
                        { 
                                Write-Host "Write access detected for " $Node 
                            } 
                } 
            } 
    } 
} 

function Find-KeyFiles($Path) { 
    $Nodes = (Get-ChildItem -Recurse $Path).FullName 
    ForEach ($Node in $Nodes) { 
	If ($Node.toString() -like "*id_rsa") {
		Write-Host "SSH key file found: " $Node
	}
        If ($Node.toString() -like "*.pkk" -or $Node.toString() -like "*.ppk" -or $Node.toString() -like "*.rnd") {
		Write-Host "Putty key file found: " $Node
	}
	If ($Node.toString() -like "*.kdbx" -or $Node.toString() -like "*.kdb") {
		Write-Host "Keypassx file found: " $Node
        }
	if ($Node.toString() -like "*.moba") {
		Write-Host MobaXterm file found: " $Node
	}
	If ($Node.toString() -like "*web.conf" -or $Node.toString() -like "*web.config") {
		Write-Host "Web config found: " $Node
	}
    } 
}
 
function Find-VulnerableSoftware($Path) { 
    $Nodes = (Get-ChildItem -Recurse $Path).FullName 
    If ($Node.toString() -like "*java.exe") {
		Write-Host "Java file found: " $Nodes " (please check manually if version vulnerable)" 
    }
} 
