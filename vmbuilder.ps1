# This script is a work in progress and is not yet complete.
# This script is intended to be run with Hyper-V enabled and the Hyper-V PowerShell module installed.

param (
    [Parameter()]
    [string]$target    = "localhost", # target host, e.g. target
    [string]$workdir,                 # working directory, default to $PSScriptRoot, careful with this.
    [string]$targetdir,               # directory to store VMs, default to $workdir/VMs
    [string]$isodir,                  # directory to store ISOs, default to $workdir/ISOs
    [String]$image     = 'ubuntu',
    [Int]$cpu          = 2,
    [String]$ram       = '4GB',
    [String]$hdd       = '32GB',
    [Switch]$seed,                     # use seed file for cloud-init true/false
    [Int]$generation   = 2,
    [String]$nettype   = 'public',     # private/public
    [String]$zwitch,                   # name of virtual switch to use or set to $image
    [String]$adapter,                  # public net adapter name.  only used if nettype is public
    [String]$VLAN,                     # VLAN ID. only used if nettype is public
    [switch]$InstallTools,             # Install packages kubectl, docker, qemu-img
    [switch]$ShowConfig,               # Show script config vars
    [switch]$DeployHostsFile,          # Append private network node names to etc/hosts
    [switch]$GetISO,                   # Download the ISO image
    [String]$ProvisionVM,              # Create and launch VM (node1, node2, ...)
    [String]$ProvisionVMs,             # Create and launch N VMs
    [switch]$GetInfo,                  # Display info about nodes
    [String]$ShowVM,                   # Show VM node N console
    [switch]$ShowVMs,                  # Show all VM consoles
    [switch]$GetTime,                  # Show time on all nodes
    [switch]$GetVMs,                   # Show all VMs
    [String]$GetVM,                    # Show VM node N info
    [switch]$SaveVMs,                  # Snapshot the VMs
    [switch]$RestoreVMs,               # Restore VMs from latest snapshots
    [switch]$StartVMs,                 # Start the VMs
    [switch]$StopVMs,                  # Hard-Stop the VMs
    [switch]$RestartVMs,               # Soft-reboot the VMs
    [switch]$ResetVMs,                 # Hard-reboot the VMs
    [switch]$ShutdownVMs,              # Soft-shutdown the VMs
    [switch]$RemoveVMs,                # Stop VMs and delete the VM files
    [switch]$GetMACs,                  # Show MAC addresses
    [switch]$GetNetAdapter,            # Show network adapters
    [switch]$GetVSwitch,               # Show virtual switches
    [switch]$ProvisionNetwork,         # Install private or public host network
    [switch]$RemoveNetwork,            # Delete the network
    [switch]$Help                      # Show help
)

$version = 'v3.0.2'

switch ($nettype) {
  'private' { 
        $adapter = 'Internal' 
#        $zwitch  = "Default Switch"   # private net switch name
#        $natnet  = "NatNet"           # private net nat net name (only used if nettype is private)
        $zwitch  = "$($image)"        # private net switch name
        $natnet  = "$($image)NatNet"  # private net nat net name (only used if nettype is private)
        $cidr    = '10.101.0'         # all private net nodes will be in this subnet behind nat
    }
  'public' {
        if ( '' -eq $adapter ) {        # nic adapter name
            $adapter = 'External'
            #write-output 'No adapter given, defaulting to $adapter'
            #write-output 'Use -GetNetAdapter to list virtual adapters'
        }
        if ( '' -eq $zwitch )  {        # public net switch name
            $zwitch  = 'External' 
            #write-output 'No switch given, defaulting to $zwitch'
            #write-output 'Use -GetVSwitch to list virtual switches'
        }  
        $natnet  = $null        # public net nat net name (only used if nettype is private)
        $cidr    = $null        # public net nodes use dhcp
    }
}

# set the working directories
if ('' -eq $workdir) {
    $workdir = "$PSScriptRoot"
}
$seeddir = "$workdir\seeds"      # This is where the cloud-init iso image files will go.
$toolsdir = "$workdir\tools"
$toolsbin = "$toolsdir\bin"
if ('' -eq $targetdir) {
  $targetdir = "$workdir\VMs"    # This is where everything will go including VM disks and config.
}
if ('' -eq $isodir) {
  $isodir = "$workdir\ISOs"      # This is where the ISO files will go.
}

# create directories if they don't exist
if (!(Test-Path $workdir)) { New-Item -itemtype directory -force -path $workdir | Out-Null }
if (!(Test-Path $seeddir)) { New-Item -itemtype directory -force -path $seeddir | Out-Null }
if (!(Test-Path $toolsdir)) { New-Item -itemtype directory -force -path $toolsdir | Out-Null }
if (!(Test-Path $toolsbin)) { New-Item -itemtype directory -force -path $toolsbin | Out-Null }
if (!(Test-Path $targetdir)) { New-Item -itemtype directory -force -path $targetdir | Out-Null }
if (!(Test-Path $isodir)) { New-Item -itemtype directory -force -path $isodir | Out-Null }


# set the image specific mac seed
switch ($image) {
  'incus'      { $macseed = '67' }
  'cloudstack' { $macseed = '43' }
  'talos'      { $macseed = '13' }
  'maas'       { $macseed = '71' }
  'ubuntu'     { $macseed = '01' }
}
$macs = @(
  "02FBB513$($macseed)00", # $($image)0
  "02FBB513$($macseed)01", # $($image)1
  "02FBB513$($macseed)02", # $($image)2
  "02FBB513$($macseed)03", # $($image)3
  "02FBB513$($macseed)04", # $($image)4
  "02FBB513$($macseed)05", # $($image)5
  "02FBB513$($macseed)06", # $($image)6
  "02FBB513$($macseed)07", # $($image)7
  "02FBB513$($macseed)08", # $($image)8
  "02FBB513$($macseed)09"  # $($image)9
)

# User and ssh keys
# $guestuser = $env:USERNAME.ToLower()
$guestuser = 'administrator'
$sshpath = "$HOME\.ssh\id_rsa.pub"
if (!(Test-Path $sshpath)) {
  Write-Host "`n please configure `$sshpath or place a pubkey at $sshpath `n"
  exit
}
$sshpub = $(Get-Content $sshpath -raw).trim()
$sshopts = @('-o LogLevel=ERROR', '-o StrictHostKeyChecking=no', '-o UserKnownHostsFile=/dev/null')

 
# utility downloads
$dockercli    = 'https://github.com/StefanScherer/docker-cli-builder/releases/download/20.10.9/docker.exe'
$kubectlcli   = 'https://dl.k8s.io/release/v1.22.0/bin/windows/amd64/kubectl.exe'
$qemuimgcli   = 'https://cloudbase.it/downloads/qemu-img-win-x64-2_3_0.zip'
$talosctlcli  = 'https://github.com/siderolabs/talos/releases/download/v1.6.7/talosctl-linux-amd64'
$incuscli     = 'https://github.com/lxc/incus/releases/latest/download/bin.windows.incus.x86_64.exe'

# iso download urls per image
switch ($image) {
  'incus'      { $isourl = "https://channels.nixos.org/nixos-23.11/latest-nixos-minimal-x86_64-linux.iso" }
  'talos'      { $isourl = "https://github.com/siderolabs/talos/releases/download/v1.6.7/metal-amd64.iso" }
  'nixos'      { $isourl = "https://channels.nixos.org/nixos-23.11/latest-nixos-minimal-x86_64-linux.iso" }
  'cloudstack' { $isourl = "https://www.releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso" }
  'maas'       { $isourl = "https://www.releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso" }  
  'ubuntu'     { $isourl = "https://www.releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso" }
  'debian'     { $isourl = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-11.1.0-amd64-netinst.iso" }
  'centos'     { $isourl = "https://mirrors.kernel.org/centos/8.4.2105/isos/x86_64/CentOS-8.4.2105-x86_64-boot.iso" }
  'alpine'     { $isourl = "https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-standard-3.14.2-x86_64.iso" }
  'arch'       { $isourl = "https://mirror.rackspace.com/archlinux/iso/2021.09.01/archlinux-2021.09.01-x86_64.iso" }
  'fedora'     { $isourl = "https://download.fedoraproject.org/pub/fedora/linux/releases/34/Server/x86_64/iso/Fedora-Server-dvd-x86_64-34-1.2.iso" }
  'rhel'       { $isourl = "https://access.redhat.com/downloads/content/69/ver=/rhel---8/8.4/x86_64/product-software" }
  'opensuse'   { $isourl = "https://download.opensuse.org/distribution/leap/15.3/iso/openSUSE-Leap-15.3-DVD-x86_64.iso" }
  'suse'       { $isourl = "https://download.suse.com/Download?buildid=5Q1X9zvQ9Qw~" }
  'gentoo'     { $isourl = "https://gentoo.osuosl.org/releases/amd64/autobuilds/20210930T214502Z/install-amd64-minimal-20210930T214502Z.iso" }
  'slackware'  { $isourl = "https://mirrors.slackware.com/slackware/slackware64-14.2-iso/slackware64-14.2-install-dvd.iso" }
  'freebsd'    { $isourl = "https://download.freebsd.org/ftp/releases/amd64/amd64/ISO-IMAGES/13.0/FreeBSD-13.0-RELEASE-amd64-disc1.iso" }
  'netbsd'     { $isourl = "https://cdn.netbsd.org/pub/NetBSD/NetBSD-9.2/amd64/installation/cdrom/boot.iso" }
  'openbsd'    { $isourl = "https://cdn.openbsd.org/pub/OpenBSD/7.0/amd64/install70.iso" }
}

# get file name from URL
$bootiso=([uri]"$($isourl)").Segments[-1]

# find the hosts file
$etchosts = "$env:windir\System32\drivers\etc\hosts"

# end of config
# ----------------------------------------------------------------------
#
# switch to the script directory
Set-Location $PSScriptRoot | Out-Null

# stop on any error
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function New-PublicNet($zwitch, $adapter) {
  New-VMSwitch -name $zwitch -allowmanagementos $true -netadaptername $adapter | Format-List
}

function New-PrivateNet($natnet, $zwitch, $cblock) {
  New-VMSwitch -name $zwitch -switchtype internal | Format-List
  New-NetIPAddress -ipaddress "$($cblock).1" -prefixlength 24 -interfacealias "vEthernet ($zwitch)" | Format-List
  New-NetNat -name $natnet -internalipinterfaceaddressprefix "$($cblock).0/24" | Format-List
}

function View-Machine($vmname) {
  vmconnect.exe localhost $vmname
}

function New-Machine($zwitch, $vmname, $cpu, $ram, $hdd, $vhdxtmpl, $cblock, $ip, $mac, $bootiso) {
  $vmdir = "$targetdir\$vmname"
  $vhdx  = "$targetdir\$vmname\$vmname.vhdx"

  # write-host "name = $name"
  # write-host "cpu = $cpu"
  # write-host "ram = $ram"
  # write-host "hdd = $hdd"
  # write-host "generation = $generation"
  # write-host "isodir\bootiso = $isodir\$bootiso"

  if (!(Test-Path $vmdir)) {
    New-Item -itemtype directory -force -path $vmdir | Out-Null
  }

  #if (!(Test-Path $vhdx)) {
  #  Copy-Item -path $vhdxtmpl -destination $vhdx -force
  #  Resize-VHD -path $vhdx -sizebytes $hdd
  #}

  $VMProperties = @{
    Name               = $vmname
    MemoryStartupBytes = $ram
    Generation         = $generation
    BootDevice         = "VHD"
    NewVHDPath         = $vhdx              
    Path               = $targetdir
    NewVHDSizeBytes    = $hdd
    SwitchName         = $zwitch
  }      #New-VM -name $vmname -memorystartupbytes $ram -generation $generation -switchname $zwitch -NewVHDPath $vhdx -NewVHDSizeBytes $hdd -path $targetdir

  New-VM @VMProperties

  if ($generation -eq 2) {
    Set-VMFirmware -vmname $vmname -enablesecureboot off
  }

  Set-VMMemory -vmname $vmname -DynamicMemoryEnabled $false

  Set-VMProcessor -vmname $vmname -count $cpu

  if (!$mac) { $mac = New-MacAddress }
  Get-VMNetworkAdapter -vmname $vmname | Set-VMNetworkAdapter -staticmacaddress $mac

  # Set VLAN on NIC if a VLAN is provided
  if ($null -ne $VLAN) {
    Set-VMNetworkAdapterVlan -VMName $VMName -VlanId $VLAN -Access
  }

  Set-VMComPort -vmname $vmname -number 2 -path \\.\pipe\$vmname

  Add-VMDvdDrive -vmname $vmname -path $isodir\$bootiso

  # disable pxe
  # $adapter=$(Get-VMNetworkAdapter -vmname $vmname)
  Set-VMFirmware $vmname -BootOrder $(Get-VMHardDiskDrive -vmname $vmname), $(Get-VMDvdDrive -vmname $vmname)

  if ($seed) {
    $seediso="seed-$($vmname).iso"
    Add-VMDvdDrive -vmname $vmname -path $seeddir\$seediso
  }

  Start-VM -name $vmname

}

function Remove-Machine($name) {
  Stop-VM $name -turnoff -confirm:$false -ea inquire # silentlycontinue
  Remove-VM $name -force -ea inquire # silentlycontinue
  Remove-Item -recurse -force $targetdir\$name
}

function Remove-PublicNet($zwitch) {
  Remove-VMswitch -name $zwitch -force -confirm:$false
}

function Remove-PrivateNet($zwitch, $natnet) {
  Remove-VMswitch -name $zwitch -force -confirm:$false
  Remove-NetNat -name $natnet -confirm:$false
}

function New-MacAddress() {
  return "02$((1..5 | ForEach-Object { '{0:X2}' -f (get-random -max 256) }) -join '')"
}

function basename($path) {
  return $path.substring(0, $path.lastindexof('.'))
}

function New-VHDXTmpl($imageurl, $srcimg, $vhdxtmpl) {
  if (!(Test-Path $workdir)) {
    mkdir $workdir | Out-Null
  }
  if (!(Test-Path $srcimg$archive)) {
    Get-File -url $imageurl -saveto $srcimg$archive
  }

  Get-Item -path $srcimg$archive | ForEach-Object { Write-Host 'srcimg:', $_.name, ([math]::round($_.length / 1MB, 2)), 'MB' }

  if ($sha256file) {
    $hash = shasum256 -shaurl "$imagebase/$sha256file" -diskitem $srcimg$archive -item $image$archive
    Write-Output "checksum: $hash"
  }
  else {
    Write-Output "no sha256file specified, skipping integrity ckeck"
  }

  if (($archive -eq '.tar.gz') -and (!(Test-Path $srcimg))) {
    tar xzf $srcimg$archive -C $workdir
  }
  elseif (($archive -eq '.xz') -and (!(Test-Path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }
  elseif (($archive -eq '.bz2') -and (!(Test-Path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }

  if (!(Test-Path $vhdxtmpl)) {
    Write-Output "vhdxtmpl: $vhdxtmpl"
    qemu-img.exe convert $srcimg -O vhdx -o subformat=dynamic $vhdxtmpl
  }

  Write-Output ''
  Get-Item -path $vhdxtmpl | ForEach-Object { Write-Host 'vhxdtmpl:', $_.name, ([math]::round($_.length / 1MB, 2)), 'MB' }
  return
}

function Get-File($url, $saveto) {
  Write-Output "downloading $url to $saveto"
  $progresspreference = 'silentlycontinue'
  Invoke-Webrequest $url -usebasicparsing -outfile $saveto # too slow w/ indicator
  $progresspreference = 'continue'
}

function Set-HostsFile($cblock, $prefix) {
  $ret = switch ($nettype) {
    'private' {
      @"
#
$prefix#
$prefix$($cblock).1 $($image)1
$prefix$($cblock).2 $($image)2
$prefix$($cblock).3 $($image)3
$prefix$($cblock).4 $($image)4
$prefix$($cblock).5 $($image)5
$prefix$($cblock).6 $($image)6
$prefix$($cblock).7 $($image)7
$prefix$($cblock).8 $($image)8
$prefix$($cblock).9 $($image)9
$prefix#
$prefix#
"@
    }
    'public' {
      ''
    }
  }
  return $ret
}

function Update-HostsFile($cblock) {
  Set-HostsFile -cblock $cblock -prefix '' | Out-File -encoding utf8 -append $etchosts
  Get-Content $etchosts
}

function Get-ImageVM() {
  return get-vm | Where-Object { ($_.name -match "$($image).*") }
}

function get-our-running-vms() {
  return get-vm | Where-Object { ($_.state -eq 'running') -and ($_.name -match "$($image).*") }
}

function shasum256($shaurl, $diskitem, $item) {
  $pat = "^(\S+)\s+\*?$([regex]::escape($item))$"

  $hash = Get-Filehash -algo sha256 -path $diskitem | ForEach-Object { $_.hash }

  $webhash = ( Invoke-Webrequest $shaurl -usebasicparsing ).tostring().split("`n") | `
    Select-String $pat | ForEach-Object { $_.matches.groups[1].value }

  if (!($hash -ieq $webhash)) {
    throw @"
    SHA256 MISMATCH:
       shaurl: $shaurl
         item: $item
     diskitem: $diskitem
     diskhash: $hash
      webhash: $webhash
"@
  }
  return $hash
}

function Get-Ctrlc() {
  if ([console]::KeyAvailable) {
    $key = [system.console]::readkey($true)
    if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
      return $true
    }
  }
  return $false;
}

function Wait-NodeInit($opts, $name) {
#  ssh $opts $guestuser@master 'sudo reboot 2> /dev/null'
  while ( ! $(ssh $opts $guestuser@master 'ls ~/.init-completed 2> /dev/null') ) {
    ### should be able to use /var/lib/cloud/instance/boot-finished instead?
    Write-Output "waiting for $name to init..."
    Start-Sleep -seconds 5
    if ( Get-Ctrlc ) { exit 1 }
  }
}

function Convert-UNCPath($path) {
  $item = Get-Item $path
  return $path.replace($item.root, '/').replace('\', '/')
}

function Convert-UNCPath2($path) {
  return ($path -replace '^[^:]*:?(.+)$', "`$1").replace('\', '/')
}

function Show-Aliases($pwsalias, $bashalias) {
  Write-Output ""
  Write-Output "powershell alias:"
  Write-Output "  write-output '$pwsalias' | Out-File -encoding utf8 -append `$profile"
  Write-Output ""
  Write-Output "bash alias:"
  Write-Output "  write-output `"``n$($bashalias.replace('\', '\\'))``n`" | Out-File -encoding utf8 -append -nonewline ~\.profile"
  Write-Output ""
  Write-Output "  -> restart your shell after applying the above"
}

##############      ##############
############## MAIN ##############
##############      ##############

Write-Output ''

#if ($args.count -eq 0) {
#  $args = @( '-help' )
#}

switch ($PSBoundParameters.Keys) {
  'Help' {
    Write-Output @"
  Create Hyper-V vm's.
  Inspect and optionally customize this script before use.

  Usage: .\vmbuilder.ps1 command+

  Commands:

       -InstallTools - Install packages kubectl, docker, qemu-img
         -ShowConfig - Show script config vars
    -DeployHostsFile - Append private network node names to etc/hosts
             -GetISO - Download the ISO image
      -ProvisionVM N - Create and launch VM (node1, node2, ...)
     -ProvisionVMs N - Create and launch N VMs
            -GetInfo - Display info about nodes
           -ShowVM N - Show VM node N console
            -ShowVMs - Show all VM consoles
            -GetTime - Show time on all nodes
             -GetVMs - Show all VMs
            -GetVM N - Show VM node N info
            -SaveVMs - Snapshot the VMs
         -RestoreVMs - Restore VMs from latest snapshots
           -StartVMs - Start the VMs
            -StopVMs - Hard-Stop the VMs
         -RestartVMs - Soft-reboot the VMs
           -ResetVMs - Hard-reboot the VMs
        -ShutdownVMs - Soft-shutdown the VMs
          -RemoveVMs - Stop VMs and delete the VM files
      -GetNetAdapter - Show network adapters
         -GetVSwitch - Show virtual switches
            -GetMACs - Show MAC addresses
   -ProvisionNetwork - Install private or public host network
      -RemoveNetwork - Delete the network
"@
  }
  'GetNetAdapter' {
    (Get-NetAdapter) | Where-Object -prop Status -eq 'Up' | where-object -prop IfDesc -cmatch 'Hyper-V Virtual' | select-object -prop name
    Write-Output ''
    Write-Output "Use the value within parentheses for -adapter setting when using -nettype public"
    Write-Output "e.g. .\vmbuilder.ps1 -nettype 'public' -adapter 'External' -showconfig"
  }
  'GetVSwitch' {
    Get-VMSwitch -SwitchType External
    Write-Output ''
    Write-Output "Use the value for -zwitch setting when using -nettype public"
    Write-Output '------------------------------------------------------------'
    Write-Output ''    
    Get-VMSwitch -SwitchType Internal
    Write-Output ''
    Write-Output "Use the value for -zwitch setting when using -nettype private"
    Write-Output "e.g. .\vmbuilder.ps1 -nettype 'private' -zwitch 'Internal' -showconfig"
  }
  'ShowMacs' {
    $cnt = 9
    0..$cnt | ForEach-Object {
      $comment = "$($image)$_"
      $comma = if ($_ -eq $cnt) { ' ' } else { ',' }
      Write-Output "  $($macs[$_]) $comma # $comment "
    }
  }
  'NewMacs' {
    $cnt = 9
    0..$cnt | ForEach-Object {
      $comment = switch ($_) { 0 { 'master' } default { "$($image)$_" } }
      $comma = if ($_ -eq $cnt) { '' } else { ',' }
      Write-Output "  '$(New-MacAddress)'$comma # $comment"
    }
  }
  'ShowConfig' {
    Write-Output "   version: $version"
    Write-Output "    target: $target"
    Write-Output "     image: $image"
    Write-Output "   workdir: $workdir"
    Write-Output " targetdir: $targetdir"
    if ($seed) {
      Write-Output "   seeddir: $seeddir"
      if ($null -ne $seediso) {
        Write-Output "   seediso: $seediso"
      } else {
        Write-Output "   seediso: seed-$($image){nodenumber}.iso"
      } 
    }
    if ($null -ne $vmdir) {
      Write-Output "     vmdir: $vmdir"
    } else {
      Write-Output "     vmdir: $targetdir\$image{nodenumber}"
    }
    Write-Output " guestuser: $guestuser"
    Write-Output "   sshpath: $sshpath"
    Write-Output "   sshopts: $sshopts"
    Write-Output "    isourl: $isourl"
    Write-Output "    isodir: $isodir"
    Write-Output "   bootiso: $bootiso"
    switch ($nettype) {
        'private' { 
            Write-Output "   nettype: $nettype"
            Write-Output "      cidr: $cidr.0/24"
            Write-Output "    switch: $zwitch"
            Write-Output "    natnet: $natnet"
        }
        'public' { 
            Write-Output "   nettype: $nettype"
            Write-Output "    switch: $zwitch"
            Write-Output "   adapter: $adapter"
        }
      }
    Write-Output "       cpu: $cpu"
    Write-Output "       ram: $ram"
    Write-Output "       hdd: $hdd"
  }
  'GetISO' {
     Get-File -url $isourl -saveto $isodir\$bootiso
  }
  'ProvisionNetwork' {
    switch ($nettype) {
      'private' { New-PrivateNet -natnet $natnet -zwitch $zwitch -cblock $cidr }
      'public' { New-PublicNet -zwitch $zwitch -adapter $adapter }
    }
  }
  'DeployHostsFile' {
    switch ($nettype) {
      'private' { Update-HostsFile -cblock $cidr }
      'public' { Write-Output "not supported for public net - use dhcp" }
    }
  }
  'ProvisionVM' {
    $num = [int]$($PSBoundParameters['ProvisionVM'])
    $node = "$($image)$($num)"
    Write-Host "Creating VM: $node"
    New-Machine -zwitch $zwitch -vmname $node -cpu $cpu -ram $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) -cblock $cidr -ip "$($num + 10)" -mac $macs[$num] -bootiso $bootiso
  }
  'ProvisionVMs' {
    $qty = [int]$($PSBoundParameters['ProvisionVMs'])
    1..$qty | ForEach-Object {
       $num=$_
       $node = "$($image)$($num)"
       Write-Host "Creating VM: $node"
       New-Machine -zwitch $zwitch -vmname $node -cpu $cpu -ram $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) -cblock $cidr -ip "$($num + 10)" -mac $macs[$num] -bootiso $bootiso
    }
  }
  'ShowVM' {
    $num = [int]$($PSBoundParameters['ShowVM'])
    $node = "$($image)$($num)"
    View-Machine -vmname $node
  }
  'ShowVMs' {
    Get-ImageVM | ForEach-Object {
      $node = $_.name
      View-Machine -vmname $node
    }
  }
  'GetInfo' {
    Get-ImageVM
  }
  'GetVMs' {
    Get-ImageVM
  }
  'RestartVMs' {
    Get-ImageVM | ForEach-Object {
      $node = $_.name
      Write-Output "`nrebooting $node"
      ssh $sshopts $guestuser@$node 'sudo reboot 2> /dev/null'
      }
  }
  'ShutdownVMs' {
    Get-ImageVM | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo shutdown -h now') }
  }
  'SaveVMs' {
    Get-ImageVM | Checkpoint-VM
  }
  'RestoreVMs' {
    Get-ImageVM | Foreach-Object { $_ | Get-VMSnapshot | Sort-Object creationtime | `
        Select-Object -last 1 | Restore-VMSnapshot -confirm:$false }
  }
  'ResetVMs' {
    Get-ImageVM | Restart-VM -Confirm:$False
  }
  'StopVMs' {
    Get-ImageVM | Stop-VM -Confirm:$False
  }
  'RemoveVMs' {
    Get-ImageVM | ForEach-Object { Remove-Machine -name $_.name }
  }
  'RemoveNetwork' {
    switch ($nettype) {
      'private' { Remove-PrivateNet -zwitch $zwitch -natnet $natnet }
      'public' { Remove-PublicNet -zwitch $zwitch }
    }
  }
  'GetTime' {
    Write-Output "local: $(Get-date)"
    Get-ImageVM | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      # ssh $sshopts $guestuser@$node "date ; if which chronyc > /dev/null; then sudo chronyc makestep ; date; fi"
      ssh $sshopts $guestuser@$node "date"
    }
  }
  'SSHALL' {
    Get-ImageVM | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      ssh $sshopts $guestuser@$node "date ; sudo id"
    }
  }
  'InstallTools' {
    #      Remove-Item $toolsdir -Force -Recurse
    if (!(Test-Path $toolsdir)) {
      New-Item -Path $workdir -Name "tools" -ItemType "directory"
    }
    if (!(Test-Path $toolsbin)) {
      New-Item -Path $workdir\tools -Name "bin" -ItemType "directory"      
    }

    # Install qemu-img
    Invoke-WebRequest -Uri "$qemuimgcli" -OutFile "$toolsdir\qemu-img.zip"
    Expand-Archive -LiteralPath "$workdir\qemu-img.zip" -DestinationPath "$toolsbin"
    Remove-Item "$toolsdir\qemu-img.zip"

    # Install kubectl
    Invoke-WebRequest -Uri "$kubectlcli" -OutFile "$toolsbin\kubectl.exe"

    # Install docker cli
    Invoke-WebRequest -Uri "$dockercli" -OutFile "$toolsbin\docker.exe"

    # Add to PATH    
    $oldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $newPath = "$oldPath;$toolsbin"    
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
  }
}



Write-Output ''
