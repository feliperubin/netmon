# -*- mode: ruby -*-
# vi: set ft=ruby :

# Author: Felipe Pfeifer Rubin
# Contact: felipe.rubin@edu.pucrs.br
#

MACHINE_NAME= "netmon"
SMB_SHARE= "netmon"
VM_MEMORY = 2048
VM_VCPUS = 2 #vCPU
NESTED_VIRT=true # Nested Virtualization support
LINKED_CLONE=true # Use Linked Clone instead of full VM
ENABLE_SYNCED_FOLDER=true # Disable Synced folder




Vagrant.configure("2") do |config|
  
  # config.vm.box = "generic/alpine38"
  config.vm.box = 'bento/ubuntu-16.04'

  config.vm.hostname = MACHINE_NAME
  # the name vagrant recognizes it, e.g. vagrant status instead of define will be MACHINE_NAME
  config.vm.define MACHINE_NAME
  config.vm.synced_folder '.', '/vagrant', enabled: ENABLE_SYNCED_FOLDER

  config.ssh.forward_x11 = true #Enables X11

  # config.vm.network "private_network", type: "dhcp"
  # Either wireless, or Thunderbolt Ethernet
  # config.vm.network "public_network", bridge: [
  # "en0",
  # "en4"
  # ],type: "dhcp"
  config.vm.network "public_network",gateway: "192.168.15.10"


  config.vm.provider :parallels do |v, override|
      # override.vm.box = "bento/ubuntu-16.04"
      
      v.linked_clone = LINKED_CLONE
      v.memory = VM_MEMORY
      v.cpus = VM_VCPUS
      required_plugins = %w( vagrant-parallels )
      required_plugins.each do |plugin|
          system "vagrant plugin install #{plugin}" unless Vagrant.has_plugin? plugin
      end
      # v.check_guest_tools = true
      v.update_guest_tools = false

      if NESTED_VIRT then
        #Enables nested virtualization
        v.customize ["set", :id, "--nested-virt", "on"]
      end
      #Enables adaptive hypervisor, better core usage
      v.customize ["set", :id, "--adaptive-hypervisor", "on"]

      #SSH without vagrant without the need of typing ssh key
      v.customize     ["set", :id, "--sync-ssh-ids","on"]
      v.customize ["set",:id, "--time-sync","on"] 
  end

  config.vm.provider :vmware_fusion do |v, override|
    v.vmx['displayname'] = MACHINE_NAME
    v.vmx['memsize'] = VM_MEMORY
    v.vmx['numvcpus'] = VM_VCPUS
    if NESTED_VIRT then
      # Enables nested virtualization
      v.vmx["vhv.enable"] = "TRUE"
    end
    # override.config.vm.network "forwarded_port", guest: 22, host: 2497, id: 'ssh'

    # Enables Retina / HiDPI
    #v.vmx["gui.fitguestusingnativedisplayresolution"] = "TRUE"
    
    # Enables Sound
    # v.vmx["sound.startconnected"] = "TRUE"
    # v.vmx["sound.present"] = "TRUE"
    # v.vmx["sound.autodetect"] = "TRUE"

  end

  config.vm.provider :virtualbox do |v, override|
    v.name = "#{MACHINE_NAME}"
    v.memory = VM_MEMORY
    v.cpus = VM_VCPUS
    v.gui = false

    if LINKED_CLONE then
      v.linked_clone = true
    end
    required_plugins = %w( vagrant-vbguest )
    required_plugins.each do |plugin|
      system "vagrant plugin install #{plugin}" unless Vagrant.has_plugin? plugin
    end
    if NESTED_VIRT then
      v.customize ["modifyvm",:id,"--hwvirtex", "on"]
      v.customize ["modifyvm",:id,"--nested-hw-virt", "on"]
      v.customize ["modifyvm",:id,"--nestedpaging", "on"]
      v.customize ["modifyvm",:id,"--largepages", "on"]
      v.customize ["modifyvm",:id,"--vtxux", "on"]
      v.customize ["modifyvm",:id,"--vtxvpid", "on"]    
    end
  end  


  config.vm.provision 'shell' do |s|
    s.inline = "echo setting up #{MACHINE_NAME}"
    config.vm.provider :vmware_fusion do |v, override|
      v.name = MACHINE_NAME
    end
    config.vm.provider :virtualbox do |v, override|
      v.name = MACHINE_NAME
    end
    config.vm.provider :parallels do |v, override|
      v.name = MACHINE_NAME
    end
  end


  
  config.vm.provision 'essentials',type: 'shell',privileged: true, run: "once", preserve_order: true, inline:
  "
    # dpkg-reconfigure locales
    locale-gen en_US.UTF-8
    echo export LC_ALL='en_US.UTF-8' >> /home/vagrant/.bashrc  
    apt-get update
    systemctl stop apt-daily.timer
    systemctl disable apt-daily.timer
    systemctl mask apt-daily.service
    systemctl daemon-reload
    apt-get remove popularity-contest

    # Additional
    ln -s /vagrant /home/vagrant/t2      
  "
  config.vm.provision 'networking',type: 'shell',privileged: true, run: "once", preserve_order: true, inline:
  "
    apt-get -y install iproute traceroute python3-pip
  "
  config.vm.provision 'x11',type: 'shell',privileged: true, run: "never", preserve_order: true, inline:
  "
    apt-get install -y xauth
    systemctl daemon-reload
    echo ForwardX11 yes >> /etc/ssh/ssh_config
    echo X11Fowarding yes >> /etc/ssh/ssh_config
    echo XAuthLocation /usr/X11/bin/xauth >> /etc/ssh/ssh_config
    echo 11UseLocalHost no >> /etc/ssh/ssh_config
  "
  config.vm.provision 'samba',type: 'shell',privileged: true, run: "never", preserve_order: true, inline:
  "
    apt-get install -y samba
    echo [#{SMB_SHARE}] >> /etc/samba/smb.conf
    echo comment = Public Shares >> /etc/samba/smb.conf
    echo path = /home/vagrant/ >> /etc/samba/smb.conf
    echo writeable = Yes >> /etc/samba/smb.conf
    echo only guest = No >> /etc/samba/smb.conf
    echo create mask = 0777 >> /etc/samba/smb.conf
    echo directory mask = 0777 >> /etc/samba/smb.conf
    echo browseable = yes >> /etc/samba/smb.conf
    echo public = yes >> /etc/samba/smb.conf
    echo inherit permissions = yes >> /etc/samba/smb.conf
    echo force user = root >> /etc/samba/smb.conf
    echo force group = root >> /etc/samba/smb.conf
    service smbd restart
  "  

end











