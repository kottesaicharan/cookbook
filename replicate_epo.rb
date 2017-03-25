#
# Author:: Jerry Yang
# Recipe:: cepo::replicate_epo
#
# Description: replicate ePO from goldimage to app server
#   - import epo registry keys from goldimage
#   - download epo files from goldimage
#
# Copyright 2016, Intel Corporation.
#

require 'win32/service'
chefenv = node.chef_environment

##################################
if (!search(:node, "role:epo_goldimage AND chef_environment:"+chefenv, :filter_result => { 'ip' => [ 'ipaddress' ]} ).empty?)
  goldimage_ip = search(:node, "role:epo_goldimage AND chef_environment:"+chefenv, :filter_result => { 'ip' => [ 'ipaddress' ]})[0]['ip']
end
##################################

if ("#{goldimage_ip}" != "")
  #stop tomcat
  service "#{node['mfs']['service_name']}" do
    only_if {::Win32::Service.exists?("#{node['mfs']['service_name']}")}
    action :stop
  end

  #create artifacts directory
  directory "#{node['artifacts']['path']}" do
    not_if { ::File.directory?("#{node['artifacts']['path']}") }
  end

  #copy epo registry keys
  batch "copy ePO registry keys" do
    code <<-EOH
	  net use \\\\#{goldimage_ip}\\IPC$ /u:#{goldimage_ip}\\#{node['local']['admin']['name']} #{node['local']['admin']['password']}
      robocopy "\\\\#{goldimage_ip}\\#{node['shared']['regkeys']['name']}" "#{node['epo']['regkeys']['path']}" /is *.reg
      net use \\\\#{goldimage_ip}\\IPC$ /D /Y
    EOH
    returns [0,1]
  end
  
  #import registry keys
  powershell_script "import epo registry key" do
    code <<-EOH
      get-childitem "#{node['epo']['regkeys']['path']}" -Filter *.reg | foreach { 
        regedit.exe /s "#{node['epo']['regkeys']['path']}\\$_" 
      }
    EOH
  end

  #copy epo files
  execute "copy epo files" do
    command <<-EOH
	  net use \\\\#{goldimage_ip}\\IPC$ /u:#{goldimage_ip}\\#{node['local']['admin']['name']} #{node['local']['admin']['password']}
      robocopy "\\\\#{goldimage_ip}\\#{node['shared']['epo']['name']}" "#{node['epo']['installed_path']}" /Z /E /SEC /PURGE /MT /R:5 /W:10 /NDL /NFL /NP /NJH /NJS /NC /NS /XF "*.tmp" "*.log" /XD "#{node['epo']['installed_path']}\server\temp","#{node['epo']['installed_path']}\server\logs","#{node['epo']['installed_path']}\DB\logs","#{node['epo']['installed_path']}\DB\UploadLicenseData","#{node['epo']['installed_path']}\installer\core\catalina-bak","#{node['epo']['installed_path']}\Apache2\conf\ssl.crt" /S /is
      net use \\\\#{goldimage_ip}\\IPC$ /D /Y
    EOH
    returns [0,1,2,3]
  end

  #start tomcat
  service "#{node['mfs']['service_name']}" do
    action :start
  end

  #wait for tomcat
  execute "wait for tomcat to start" do
    command "sleep 180"
  end
end