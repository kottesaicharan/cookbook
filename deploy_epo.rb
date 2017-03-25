#
# Author:: Kotte, SaicharanX <saicharanx.kotte@intel.com>; Yang, Jerry <jerry.yang@intel.com>
# Recipe:: cepo::deploy_epo
#
# Description:
#   - install vc redist packages
#   - install epo
#   - config epo settings for cloud
#   - export epo registry keys
#
# Copyright 2016, Intel Corporation.
#
chefenv = node.chef_environment

begin
ruby_block 'return if not ready' do
    block do
      # if db_bootstrap_done == false
       db_wait_resource = Chef::Resource::EpoWaitHelper.new('epo_db', chefenv)
       unless db_wait_resource.db_ready?
         Chef::Log.error('db bootstrap is not done. Exiting the chef client.')
         raise 'db bootstrap is not done. Exiting the chef client.'
       end
     end
     action :run
   end
end

begin
ruby_block 'return if not ready' do
    block do
      # if repo_bootstrap_done == false
       repo_wait_resource = Chef::Resource::EpoWaitHelper.new('epo_repo_server', chefenv)
       unless repo_wait_resource.repo_ready?
         Chef::Log.error('repo bootstrap is not done. Exiting the chef client.')
         raise 'repo bootstrap is not done. Exiting the chef client.'
       end
     end
     action :run
   end
end

#create artifacts directory
directory "#{node['artifacts']['path']}" do
  not_if { ::File.directory?("#{node['artifacts']['path']}") }
end

iaas_provider = node['IAAS_PROVIDER']

#get epo build package
if (iaas_provider == 'AWS')
  powershell_script "Download the epo package" do
    code <<-EOH
      Read-S3Object -BucketName #{node['s3']['bucket']} -Key #{node['package']['epo']} -File #{node['artifacts']['path']}\\epobuild.zip
    EOH
    not_if {::File.exists?("#{node['artifacts']['path']}\\epobuild.zip")}
  end

  windows_zipfile "#{node['epo_build']['path']}" do
    source "#{node['artifacts']['path']}\\epobuild.zip"
    action :unzip
    not_if {::File.exists?("#{node['epo_build']['path']}\\Setup.exe")}
  end
else
  windows_zipfile "#{node['epo_build']['path']}" do
    source "#{node['package']['epo']}"
    action :unzip
    not_if {::File.exists?("#{node['epo_build']['path']}\\Setup.exe")}
  end
end

#get product packages
if (iaas_provider == 'AWS')
  powershell_script "Download the product packages" do
    code <<-EOH
      Read-S3Object -BucketName #{node['s3']['bucket']} -Key #{node['package']['products']} -File #{node['artifacts']['path']}\\products.zip
    EOH
    not_if {::File.exists?("#{node['artifacts']['path']}\\products.zip")}
  end

  windows_zipfile "#{node['artifacts']['path']}" do
    source "#{node['artifacts']['path']}\\products.zip"
    action :unzip
	not_if { ::File.directory?("#{node['extensions']['path']}") }
  end
else
#TODO
  batch "download product packages" do
    code <<-EOH
	  REM net use \\\\#{goldimage_ip}\\IPC$ /u:#{goldimage_ip}\\#{node['local']['admin']['name']} #{node['local']['admin']['password']}
      robocopy "['product']['package_path']" "#{node['packages']['path']}"
      REM net use \\\\#{goldimage_ip}\\IPC$ /D /Y
    EOH
    returns [0,1]
  end
end

#download LB Certificate
directory "#{node['certificates']['path']}" do
  not_if { ::File.directory?("#{node['certificates']['path']}") }
end

powershell_script "Download LB certificate" do
  code <<-EOH
    Read-S3Object -BucketName #{node['s3']['bucket']} -Key #{node['package']['certificate']} -File #{node['certificates']['path']}/certificate.pem
  EOH
  not_if {::File.exists?("#{node['certificates']['path']}/certificate.pem")}
end

file "C:\\reboot_first.txt" do
  not_if {::File.exists?( "C:\\reboot_first.txt")}
	notifies :reboot_now, 'reboot[Restart Computer]', :immediately
end

reboot 'Restart Computer' do
  action :nothing
  reason 'Need to reboot when the run completes successfully.'
end

require 'win32/service'
node.set['sql_server']['accept_eula'] = node['EPO']['SQL_ACCEPT_EULA']
node.set['sql_server']['version'] = node['EPO']['SQL_VERSION']
include_recipe "sql_server::client"

file "C:\\deployed.txt" do
  action :delete
  only_if {::File.exists?( "C:\\deployed.txt")}
  not_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
end

##################################
if (!search(:node, "role:epo_db AND chef_environment:"+chefenv, :filter_result => { 'ip' => [ 'ipaddress' ]} ).empty?)
  db_ip = search(:node, "role:epo_db AND chef_environment:"+chefenv, :filter_result => { 'ip' => [ 'ipaddress' ]})[0]['ip']
end

if (!search(:node, "role:epo_repo_server AND chef_environment:"+chefenv, :filter_result => { 'ip' => [ 'ipaddress' ]} ).empty?)
  repo_ip = search(:node, "role:epo_repo_server AND chef_environment:"+chefenv, :filter_result => { 'ip' => [ 'ipaddress' ]})[0]['ip']
end
##################################

#install curl
if (iaas_provider == 'AWS')
  powershell_script "Download the curl package" do
    code <<-EOH
      Read-S3Object -BucketName #{node['s3']['bucket']} -Key #{node['package']['curl']} -File #{node['artifacts']['path']}\\curl.zip
    EOH
    not_if {::File.exists?("#{node['artifacts']['path']}\\curl.zip")}
  end

  windows_zipfile "C:\\" do
    source "#{node['artifacts']['path']}\\curl.zip"
    action :unzip
  not_if {::File.exists?("C:\\cURL\\bin\\curl.exe")}
  end
else
  windows_zipfile "C:\\" do
    source "#{node['package']['curl']}"
    action :unzip
  not_if {::File.exists?("C:\\cURL\\bin\\curl.exe")}
  end
end

#Install vc redist packages
windows_package 'Microsoft Visual C++ 2005 Redistributable 32Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VCRedist\\vcredist_x86.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VCRedist\\vcredist_x86.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{710f4c1c-cc18-4c49-8cbf-51240c89a1a2}",:x86_64)}
end

windows_package 'Microsoft Visual C++ 2008 Redistributable 64Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VC08Redist\\vcredist_x64.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VC08Redist\\vcredist_x64.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{8220EEFE-38CD-377E-8595-13398D740ACE}",:x86_64)}
end

windows_package 'Microsoft Visual C++ 2008 Redistributable 32Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VC08Redist\\vcredist_x86.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VC08Redist\\vcredist_x86.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{9A25302D-30C0-39D9-BD6F-21E6EC160475}",:x86_64)}
end

windows_package 'Microsoft Visual C++ 2010 Redistributable 64Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VC10Redist\\vcredist_x64.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VC10Redist\\vcredist_x64.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{1D8E6291-B0D5-35EC-8441-6616F567A0F7}",:x86_64)}
end

windows_package 'Microsoft Visual C++ 2010 Redistributable 32Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VC10Redist\\vcredist_x86.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VC10Redist\\vcredist_x86.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}",:x86_64)}
end

windows_package 'Microsoft Visual C++ 2015 Redistributable 64Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VC15Redist\\VC_redist.x64.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VC15Redist\\VC_redist.x64.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{3ee5e5bb-b7cc-4556-8861-a00a82977d6c}",:x86_64)}
end

windows_package 'Microsoft Visual C++ 2015 Redistributable 32Bit' do
  source "#{node['epo_build']['path']}\\Setup\\VC15Redist\\VC_redist.x86.exe"
  installer_type :custom
  options '/q'
  only_if {::File.exists?("#{node['epo_build']['path']}\\Setup\\VC15Redist\\VC_redist.x86.exe")}
  not_if {registry_key_exists?("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{23daf363-3020-4059-b3ae-dc4ad39fed19}",:x86_64)}
end

if ("#{repo_ip}" != "" && "#{db_ip}" != "")
  #install epo
  execute "install epo" do
    command <<-EOH
      #{node['epo_build']['path']}\\setup.exe /qn MFSADMINUSERNAME_UE=#{node['epo']['param']['MFSADMINUSERNAME_UE']} MFSADMINPASSWORD_UE=#{node['epo']['param']['MFSADMINPASSWORD_UE']} MFSADMINVERIFYPASSWORD_UE=#{node['epo']['param']['MFSADMINPASSWORD_UE']} MFSDATABASESERVERNAME=#{db_ip} MFSDATABASEPORT=#{node['epo']['param']['MFSDATABASEPORT']} MFSDATABASENAME=#{node['epo']['param']['MFSDATABASENAME']} MFSDATABASEUSERNAME_UE=#{node['epo']['param']['MFSDATABASEUSERNAME_UE']} MFSDATABASEPASSWORD_UE=#{node['epo']['param']['MFSDATABASEPASSWORD_UE']} AGENTPORT=#{node['epo']['param']['AGENTPORT']} AGENTSECUREPORT=#{node['epo']['param']['AGENTSECUREPORT']} TOMCATSECUREPORT=#{node['epo']['param']['TOMCATSECUREPORT']} MFSDATABASEAUTHENTICATION=#{node['epo']['param']['MFSDATABASEAUTHENTICATION']} SQLUDPPORTISENABLED=#{node['epo']['param']['SQLUDPPORTISENABLED']} IGNOREPROPINI=#{node['epo']['param']['IGNOREPROPINI']} LICENSEKEY=#{node['epo']['param']['LICENSEKEY']} SKIPAUTOPRODINST=#{node['epo']['param']['SKIPAUTOPRODINST']} MFSKEYSTOREPASSWORD_UE=#{node['epo']['param']['MFSKEYSTOREPASSWORD_UE']} MFSVERIFYKEYSTOREPASSWORD=#{node['epo']['param']['MFSVERIFYKEYSTOREPASSWORD']} ENABLETELEMETRY=#{node['epo']['param']['ENABLETELEMETRY']} DISABLEAH=#{node['epo']['param']['DISABLEAH']} MFS_SYSTEM_PASSWORD=#{node['epo']['param']['MFS_SYSTEM_PASSWORD']} MFS_OPS_PASSWORD=#{node['epo']['param']['MFS_OPS_PASSWORD']} MFS_TENANT_PASSWORD=#{node['epo']['param']['MFS_TENANT_PASSWORD']} CLUSTERID=#{node['epo']['param']['CLUSTERID']} MCAFEECLOUD=#{node['epo']['param']['MCAFEECLOUD']} STARTUPRUNLEVEL=#{node['epo']['param']['STARTUPRUNLEVEL']}
    EOH
    action :run
    not_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
  end

  #configure firewall rule
  powershell_script 'Modify server.xml' do
    code <<-EOH
	  Get-NetFirewallRule -DisplayName "McAfee ePolicy Orchestrator * Application Server" | Set-NetFirewallRule -Profile Public,private
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Modidy server.xml
  powershell_script 'Modify server.xml' do
    code <<-EOH
      #get content of server.xml
      $serverXmlFile = "#{node['epo']['installed_path']}\\Server\\conf\\server.xml"
      $serverXml = [xml] (get-content $serverXmlFile)
      $epoVersion = #{node['epo']['version']}

      #add connector id="agentHandlerToEPO.https"
      Write-Host "adding a connector for agentHandlerToEPO.https"
      $serviceNode =  $serverXml.Server.Service
      $xmlContent = [Xml]'<Connector id="agentHandlerToEPO.https" SSLEnabled="true" port="443" maxHttpHeaderSize="8192" maxThreads="150" minSpareThreads="25" enableLookups="false" disableUploadTimeout="true" acceptCount="100" scheme="https" secure="true" clientAuth="want" sslProtocol="TLS" keystoreFile="keystore/server.keystore" keystorePass="snowcap" truststoreFile="keystore/certAuthCa.truststore" truststorePass="snowcap" URIEncoding="UTF-8" server="Undefined" ciphers="SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA, SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA, SSL_RSA_WITH_3DES_EDE_CBC_SHA, SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" />'
      $newNode = $serverXml.ImportNode($xmlContent.connector, $true)
      $serviceNode.insertBefore($newNode, $serviceNode.Engine)
      Write-Host "Connector for agentHandlerToEPO.https is added"

      #Modify the values of keystorePass and truststorePass
      foreach ($connector in $serviceNode.Connector) {
          if (!$keystorePass -and $connector.keystorePass -and ($connector.keystorePass -notlike 'snowcap')) {
              $keystorePass = $connector.keystorePass
              $truststorePass = $connector.truststorePass
          }
      }

      $serviceNode.Connector | Where {$_.keystorePass} | ForEach-Object {
          if ($_.keystorePass -notlike $keystorePass) {
              $_.keystorePass = $keystorePass
          }
      }

      $serviceNode.Connector | Where {$_.truststorePass} | ForEach-Object {
          if ($_.truststorePass -notlike $truststorePass) {
              $_.truststorePass = $truststorePass
          }
      }

      #add valve className="org.apache.catalina.valves.RemoteIpValve"
      write-host "Add a valves for org.apache.catalina.valves.RemoteIpValve"
      $hostNode =  $serverXml.Server.Service.Engine.Host
      $xmlContent = [Xml]'<Valve className="org.apache.catalina.valves.RemoteIpValve" internalProxies="*.*.*.*" remoteIpHeader="x-forwarded-for" proxiesHeader="x-forwarded-by" protocolHeader="x-forwarded-proto" httpServerPort="8080" httpsServerPort="443" />'
      $newNode = $serverXml.ImportNode($xmlContent.valve, $true)
      $hostNode.AppendChild($newNode)
      Write-Host "Valves for org.apache.catalina.valves.RemoteIpValve is added"

      #Modify the redirectPort to "" for  Port 8080 connector
      Write-host "Modify the redirectPort to `"`" for  Port 8080 connector"
      $connector = $serviceNode.Connector | Where {$_.Port -like "8080"}
      $connector.redirectPort = ""
      Write-host "RedirectPort value of Port 8080 connector is modified"

      #save to the file
      $serverXml.Save($serverXmlFile)
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Create new ssl.crt
  directory "#{node['epo']['installed_path']}\\Apache2\\conf\\ssl.crt" do
    not_if { ::File.directory?("#{node['epo']['installed_path']}\\Apache2\\conf\\ssl.crt") }
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
  end

  #Generate apache ssl certificate
  execute 'generate ssl certificate' do
    command <<-EOH
      rundll32.exe "#{node['epo']['installed_path']}\\ahsetup.dll" RunDllGenCerts #{node['ipaddress']} #{node['epo']['console_port']} admin #{node['epo']['admin_pwd']} "#{node['epo']['installed_path']}\\apache2\\conf\\ssl.crt"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Restart Tomcat
  service "#{node['mfs']['service_name']}" do
    action :restart
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #wait for tomcat
  ruby_block 'Wait for Tomcat to start' do
    block do
      sleep(180)
	end
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Disable master repository update task
  execute "disable master repository update task" do
    command <<-EOH
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/scheduler.updateServerTask?taskName=Update%20Master%20Repository&status=disabled"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Setup User Analytics
  cookbook_file "#{node['artifacts']['path']}\\SetUserAnalytics.sql" do
    source '/sqlScripts/SetUserAnalytics.sql'
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  execute 'Setup User Analytics' do
    command <<-EOH
    "#{node['sqlcmd']['path']}\\SQLCMD.EXE" -S "#{db_ip},#{node['sql_server']['port']}" -d "#{node['sql_server']['db_name']}" -U "sa" -P "#{node['sql_server']['sa_pwd']}" -i "#{node['artifacts']['path']}\\SetUserAnalytics.sql" -v name='#{node['User_Analytics']['name']}' -v app='#{node['User_Analytics']['app']}' -v report='#{node['User_Analytics']['report']}' -v enabled='true'
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Setup BPS
  cookbook_file "#{node['artifacts']['path']}\\SetupBPS.sql" do
    source '/sqlScripts/SetupBPS.sql'
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  execute 'Setup BPS' do
    command <<-EOH
      "#{node['sqlcmd']['path']}\\SQLCMD.EXE" -S "#{db_ip},#{node['sql_server']['port']}" -d "#{node['sql_server']['db_name']}" -U "sa" -P "#{node['sql_server']['sa_pwd']}" -i "#{node['artifacts']['path']}\\SetupBPS.sql" -v myAcnt="#{node['bps']['my_account']}" usrMgmt="#{node['bps']['user_management']}" lgnURL="#{node['bps']['saml_logon']}" lgoutURL="#{node['bps']['saml_logoff']}" enKey="#{node['bps']['saml_encryption_key']}" lcnsUtlzn="#{node['bps']['license_utiliztion']}" timeout="#{node['bps']['saml_timeout']}"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #setup cloud host name
  cookbook_file "#{node['artifacts']['path']}\\SetupCloudHost.sql" do
    source '/sqlScripts/SetupCloudHost.sql'
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  execute 'setup cloud host name' do
    command <<-EOH
      "#{node['sqlcmd']['path']}\\SQLCMD.EXE" -S "#{db_ip},#{node['sql_server']['port']}" -d "#{node['sql_server']['db_name']}" -U "sa" -P "#{node['sql_server']['sa_pwd']}" -i "#{node['artifacts']['path']}\\SetupCloudHost.sql" -v cldHstNme="#{node['cloud_host']['dns']}" -v lbHttpsPort="#{node['cloud_host']['port']}"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Setup email server
  execute "Setup email server" do
    command <<-EOH
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/epo.cmd.registerEmailServer?adminEmail=#{node['smtp']['admin_email']}&serverName=#{node['smtp']['server']}&serverPort=#{node['smtp']['port']}"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Alter cert. length
  cookbook_file "#{node['artifacts']['path']}\\AlterCertLength.sql" do
    source '/sqlScripts/AlterCertLength.sql'
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  execute 'Alter cert. length' do
    command <<-EOH
      "#{node['sqlcmd']['path']}\\SQLCMD.EXE" -S "#{db_ip},#{node['sql_server']['port']}" -d "#{node['sql_server']['db_name']}" -U "sa" -P "#{node['sql_server']['sa_pwd']}" -i "#{node['artifacts']['path']}\\AlterCertLength.sql"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Alter sp_ePOCert
  cookbook_file "#{node['artifacts']['path']}\\AlterSPEpoCert.sql" do
    source '/sqlScripts/AlterSPEpoCert.sql'
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  execute 'Alter sp_ePOCert' do
    command <<-EOH
      "#{node['sqlcmd']['path']}\\SQLCMD.EXE" -S "#{db_ip},#{node['sql_server']['port']}" -d "#{node['sql_server']['db_name']}" -U "sa" -P "#{node['sql_server']['sa_pwd']}" -i "#{node['artifacts']['path']}\\AlterSPEpoCert.sql"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #import LB certificate
  batch "import LB certificate" do
      code <<-EOH
        C:\\cURL\\bin\\curl.exe -k -u #{node['epo']['param']['MFSADMINUSERNAME_UE']}:#{node['epo']['admin_pwd']} "https://localhost/remote/epo.command.saveLBCertToDb" -F certFile=@#{node['certificates']['path']}/certificate.pem
      EOH
	  not_if {::File.exists?( "C:\\deployed.txt")}
    end  
		
  #Setup master repository
  execute "setup master repository" do
    command <<-EOH
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/RepositoryMgmt.moveMasterRepositoryCmd?newUNCPath=\\\\#{repo_ip}\\#{node['repository']['master']}&UNCUser=#{node['master_repo']['user']}&UNCPass=#{node['master_repo']['password']}"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Create distributed repository
  execute "Create distributed repository" do
    command <<-EOH
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/RepositoryMgmt.createHttpRepository?name=#{node['dist_repo']['name']}&url=#{node['cdn']['dns']}&uncPath=\\\\#{repo_ip}\\#{node['repository']['dist']}&uploadUser=#{repo_ip}\\#{node['dist_repo']['user']}&uploadPassword=#{node['dist_repo']['password']}"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Disable local master repository from MA_EX
  execute "Disable local master repository from MA_EX" do
    command <<-EOH
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/EPOAGENTMETA.disableMasterRepositoryAccess"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Import SSL Certificate
  execute 'Import SSL Certificate' do
    command <<-EOH
      "#{node['epo']['installed_path']}\\JRE\\bin\\keytool.exe" -import -alias #{node['ssl_cert']['alias']} -noprompt -file "#{node['certificates']['path']}/certificate.pem" -keystore "#{node['ssl_cert']['keystore']['path']}" -storepass #{node['ssl_cert']['password']}
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Disable all AHs
  cookbook_file "#{node['artifacts']['path']}\\DisableAHs.sql" do
    source '/sqlScripts/DisableAHs.sql'
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  execute 'Disable all AHs' do
    command <<-EOH
      "#{node['sqlcmd']['path']}\\SQLCMD.EXE" -S "#{db_ip},#{node['sql_server']['port']}" -d "#{node['sql_server']['db_name']}" -U "sa" -P "#{node['sql_server']['sa_pwd']}" -i "#{node['artifacts']['path']}\\DisableAHs.sql"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #Modidy server.ini
  powershell_script 'Modify server.ini' do
    code <<-EOH
    $serverini = "#{node['epo']['installed_path']}\\DB\\server.ini"
    (gc $serverini) | select-string -pattern 'IsAgentHandlerPrimary*' -notmatch | Out-File $serverini
    (gc $serverini) | select-string -pattern 'LastRegisteredServer*' -notmatch | Out-File $serverini
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #restart tomcat
  service "#{node['mfs']['service_name']}" do
    action :restart
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #wait for tomcat
  ruby_block 'Wait for Tomcat to start' do
    block do
	  sleep(180)
    end
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #setup ah groups
  batch "setup ah groups" do
    code <<-EOH
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/AgentMgmt.createAgentHandlerGroup?groupName=#{node['external']['ah']['group']['name']}&enabled=#{node['external']['ah']['group']['enable']}&loadBalancerSet=#{node['external']['ah']['group']['lbset']}&virtualIP=#{node['external']['ah']['group']['ip']}&virtualDNSName=#{node['external']['ah']['group']['dns']}&virtualNetBiosName=#{node['external']['ah']['group']['bios']}"
      c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/AgentMgmt.createAgentHandlerGroup?groupName=#{node['internal']['ah']['group']['name']}&enabled=#{node['internal']['ah']['group']['enable']}&loadBalancerSet=#{node['internal']['ah']['group']['lbset']}&virtualIP=#{node['internal']['ah']['group']['ip']}&virtualDNSName=#{node['internal']['ah']['group']['dns']}&virtualNetBiosName=#{node['internal']['ah']['group']['bios']}"
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #setup ah assignments
  execute "setup ah assignments" do
    if node['mfs']['service_name'] >= "5.5.0"
      command <<-EOH
        c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/AgentMgmt.createAgentHandlerAssignment?assignmentId=#{node['internal']['ah']['assignment']['id']}&assignmentName=#{node['internal']['ah']['assignment']['name']}&handlerOrGroups=#{node['internal']['ah']['assignment']['group']}&ipRanges=#{node['internal']['ah']['assignment']['iprange']}&useAllHandlers=#{node['internal']['ah']['assignment']['allhandler']}"
        c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/AgentMgmt.createAgentHandlerAssignment?assignmentId=#{node['external']['ah']['assignment']['id']}&assignmentName=#{node['external']['ah']['assignment']['name']}&handlerOrGroups=#{node['external']['ah']['assignment']['group']}&ipRanges=#{node['external']['ah']['assignment']['iprange']}&useAllHandlers=#{node['external']['ah']['assignment']['allhandler']}"
      EOH
    else
      command <<-EOH
        c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/AgentMgmt.createAgentHandlerAssignment?assignmentId=#{node['internal']['ah']['assignment']['id']}&assignmentName=#{node['internal']['ah']['assignment']['name']}&handlerOrGroups=#{node['internal']['ah']['assignment']['group']}&subnetMasks=#{node['internal']['ah']['assignment']['iprange']}&useAllHandlers=#{node['internal']['ah']['assignment']['allhandler']}"
        c:\\curl\\bin\\curl -k -u admin:#{node['epo']['admin_pwd']} "https://localhost/remote/AgentMgmt.createAgentHandlerAssignment?assignmentId=#{node['external']['ah']['assignment']['id']}&assignmentName=#{node['external']['ah']['assignment']['name']}&handlerOrGroups=#{node['external']['ah']['assignment']['group']}&subnetMasks=#{node['external']['ah']['assignment']['iprange']}&useAllHandlers=#{node['external']['ah']['assignment']['allhandler']}"
      EOH
    end
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #install product extensions
  extensions = Dir.glob("#{node['extensions']['path']}/*.zip")
  extensions.each do |extension|
    batch "Install Product extension #{extension}" do
      code <<-EOH
        C:\\cURL\\bin\\curl.exe -k -u #{node['epo']['param']['MFSADMINUSERNAME_UE']}:#{node['epo']['admin_pwd']} "https://localhost/remote/ext.install" -F extension=@#{extension}
        REM DEL /q "#{node['extensions']['path']}/#{extension}"
      EOH
	  not_if {::File.exists?( "C:\\deployed.txt")}
    end  
  end

  #check in product packages
  packages = Dir.glob("#{node['packages']['path']}/*.zip")
  packages.each do |package|
    batch "Check in product package #{package}" do
      code <<-EOH
        @echo on
        C:\\cURL\\bin\\curl.exe -k -u #{node['epo']['param']['MFSADMINUSERNAME_UE']}:#{node['epo']['admin_pwd']} "https://localhost/remote/repository.checkInPackage?branch=Current&packageLocation=#{package}"
until File.exists?#{node['epo']['param']['MFSADMINUSERNAME_UE']}:#{node['epo']['admin_pwd']}
sleep 60  
end        
        #timeout 120 /nobreak
        #REM DEL /q "#{node['packages']['path']}/#{package}"
		@echo off
      EOH
      #not_if {::File.exists?( "C:\\deployed.txt")}
    end
  end
  
  #repository pull now
  execute "pull content to repository" do
    command <<-EOH
      C:\\cURL\\bin\\curl.exe -k -u #{node['epo']['param']['MFSADMINUSERNAME_UE']}:#{node['epo']['admin_pwd']} "https://localhost/remote/repository.pull?sourceRepository=McAfeeHttp&targetBranch=Current"
    EOH
    not_if {::File.exists?( "C:\\deployed.txt")}
  end
  
  #repository replication
  execute "replicate repository" do
    command <<-EOH
      C:\\cURL\\bin\\curl.exe -k -u #{node['epo']['param']['MFSADMINUSERNAME_UE']}:#{node['epo']['admin_pwd']} "https://localhost/remote/repository.replicate?incremental=true"
    EOH
    not_if {::File.exists?( "C:\\deployed.txt")}
  end
  
  #create regkeys directory
  directory "#{node['epo']['regkeys']['path']}" do
    not_if { ::File.directory?("#{node['epo']['regkeys']['path']}") }
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
  end

  #Exporting ePO reg keys
  batch "Exporting ePO reg keys" do
    code <<-EOH
      reg export "HKLM\\SOFTWARE\\Network Associates\\ePolicy Orchestrator" #{node['epo']['regkeys']['path']}\\epo.reg /y
      reg export "HKLM\\SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator" #{node['epo']['regkeys']['path']}\\epo32.reg /y
      reg export "HKLM\\SOFTWARE\\Wow6432Node\\McAfee\\ePolicy Orchestrator" #{node['epo']['regkeys']['path']}\\mfs.reg /y
      reg export "HKLM\\SYSTEM\\CurrentControlSet\\services\\#{node['mfs']['service_name']}" #{node['epo']['regkeys']['path']}\\tomcat_service.reg /y
      reg export "HKLM\\SYSTEM\\CurrentControlSet\\services\\MCAFEEAPACHESRV" #{node['epo']['regkeys']['path']}\\mcafee_apachesrv.reg /y
      reg export "HKLM\\SYSTEM\\CurrentControlSet\\services\\MCAFEEEVENTPARSERSRV" #{node['epo']['regkeys']['path']}\\mcafee_event.reg /y
      reg export "HKLM\\SOFTWARE\\Wow6432node\\Apache Software Foundation" #{node['epo']['regkeys']['path']}\\asf.reg /y
    EOH
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  #enable shared drives
  powershell_script "enable shared drives" do
    code <<-EOH
      $sharedDrives = @()
      get-WmiObject -class Win32_Share | foreach {$sharedDrives += $_.Name}
      if ($sharedDrives -notcontains "#{node['shared']['epo']['name']}") {
        net share #{node['shared']['epo']['name']}="#{node['epo']['installed_path']}" "/GRANT:Everyone,FULL"
      }
      if ($sharedDrives -notcontains "#{node['shared']['regkeys']['name']}") {
        net share #{node['shared']['regkeys']['name']}="#{node['epo']['regkeys']['path']}" "/GRANT:Everyone,FULL"
      }
    EOH
    only_if { ::File.directory?("#{node['epo']['regkeys']['path']}") }
    not_if {::File.exists?( "C:\\deployed.txt")}
  end

  file "C:\\deployed.txt" do
    not_if {::File.exists?( "C:\\deployed.txt")}
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
  end

  ruby_block 'Set goldimage bootsrapping flag' do
    block do
      node.set['goldimage']['bootstrap']['done'] = true
      node.save
    end
    action :run
    only_if { node['goldimage']['bootstrap']['done'] == false }
  end
end
