## 如何在 overcloud 里设置 Baremetal as a Service

### 定义 overcloud baremetal provisioning 网络
```
# 定义 overcloud provisioning 虚拟网络
cat > /tmp/oc-provisioning.xml <<EOF
<network>
  <name>oc-provisioning</name>
  <ip address="192.0.3.254" netmask="255.255.255.0"/>
</network>
EOF

virsh net-define /tmp/oc-provisioning.xml
virsh net-autostart oc-provisioning
virsh net-start oc-provisioning

overcloud controller 需要有网卡连接这个网络
overcloud baremetal node 也需要有网卡连接这个网络


需要配置 provisioning 网络和 oc-provisioning 网络间的路由
目前采取的方式是用 zebra 实现
参考：https://github.com/wangjun1974/tips/blob/master/os/miscs.md#%E5%AE%89%E8%A3%85%E9%85%8D%E7%BD%AE%E8%B7%AF%E7%94%B1%E8%BD%AF%E4%BB%B6-zebra


```

### 检查 overcloud 节点连接 overcloud baremetal provisioning 网络
```
控制节点
controller0 - nic2 - oc-provisioning
controller1 - nic2 - oc-provisioning
controller2 - nic2 - oc-provisioning

Baremetal 节点
baremetal node1 - nic2 - oc-provisioning
```

### 配置 controller 的 nic-config
```
修改 templates/network/config/bond-with-vlans/controller 文件

添加 br-baremetal 部分
              - type: ovs_bridge
                name: br-baremetal
                use_dhcp: false
                members:
                - type: interface
                  name: ens5

参考以下 diff 结果，注意：ovs bond 不支持 slave，因此取消了 bond1
--- controller.yaml     2021-09-10 15:45:29.026938030 +0800
+++ controller.yaml.sav 2021-09-08 09:22:42.575230348 +0800
@@ -197,7 +197,7 @@
             $network_config:
               network_config:
               - type: interface
-                name: ens3
+                name: nic1
                 mtu:
                   get_param: ControlPlaneMtu
                 use_dhcp: false
@@ -216,22 +216,23 @@
                   get_param: DnsServers
                 domain:
                   get_param: DnsSearchDomains
-                mtu:
-                  get_param: ExternalMtu
-                addresses:
-                - ip_netmask:
-                    get_param: ExternalIpSubnet
-                routes:
-                  list_concat_unique:
-                    - get_param: ExternalInterfaceRoutes
-                    - - default: true
-                        next_hop:
-                          get_param: ExternalInterfaceDefaultRoute
                 members:
-                - type: interface
-                  name: ens4
+                - type: ovs_bond
+                  name: bond1
                   mtu:
                     get_attr: [MinViableMtu, value]
+                  ovs_options:
+                    get_param: BondInterfaceOvsOptions
+                  members:
+                  - type: interface
+                    name: nic2
+                    mtu:
+                      get_attr: [MinViableMtu, value]
+                    primary: true
+                  - type: interface
+                    name: nic3
+                    mtu:
+                      get_attr: [MinViableMtu, value]
                 - type: vlan
                   mtu:
                     get_param: StorageMtu
@@ -276,12 +277,20 @@
                   routes:
                     list_concat_unique:
                       - get_param: TenantInterfaceRoutes
-              - type: ovs_bridge
-                name: br-baremetal
-                use_dhcp: false
-                members:
-                - type: interface
-                  name: ens5
+                - type: vlan
+                  mtu:
+                    get_param: ExternalMtu
+                  vlan_id:
+                    get_param: ExternalNetworkVlanID
+                  addresses:
+                  - ip_netmask:
+                      get_param: ExternalIpSubnet
+                  routes:
+                    list_concat_unique:
+                      - get_param: ExternalInterfaceRoutes
+                      - - default: true
+                          next_hop:
+                            get_param: ExternalInterfaceDefaultRoute
 outputs:
   OS::stack_id:
     description: The OsNetConfigImpl resource.

```

### 修改 templates/environment/network-environments.yaml 文件
```
添加以下内容

  ############################
  #  Neutron configuration   #
  ############################
  NeutronBridgeMappings: "datacentre:br-ex,baremetal:br-baremetal"
  NeutronFlatNetworks: datacentre,baremetal
```

### 生成 templates/ironic.yaml 文件
```
cat > templates/ironic.yaml <<EOF
parameter_defaults:
  ############################
  #  Scheduler configuration #
  ############################
  NovaSchedulerDefaultFilters:
    - "RetryFilter"
    - "AvailabilityZoneFilter"
    - "ComputeFilter"
    - "ComputeCapabilitiesFilter"
    - "ImagePropertiesFilter"
    - "ServerGroupAntiAffinityFilter"
    - "ServerGroupAffinityFilter"
    - "PciPassthroughFilter"
    - "NUMATopologyFilter"
    - "AggregateInstanceExtraSpecsFilter"

  ############################
  #  Ironic Cleaning Method  #
  ############################
  IronicCleaningDiskErase: metadata
EOF
```

### 生成部署脚本
```
cat > deploy-ironic-overcloud.sh <<'EOF'
#!/bin/bash
THT=/usr/share/openstack-tripleo-heat-templates/
CNF=~/templates/

source ~/stackrc
openstack overcloud deploy --debug --templates $THT \
-r $CNF/roles_data.yaml \
-n $CNF/network_data.yaml \
-e $THT/environments/network-isolation.yaml \
-e $CNF/environments/network-environment.yaml \
-e $CNF/environments/net-bond-with-vlans.yaml \
-e $THT/environments/services/ironic-overcloud.yaml \
-e $THT/environments/services/ironic-inspector.yaml \
-e ~/containers-prepare-parameter.yaml \
-e $CNF/node-info.yaml \
-e $CNF/ironic.yaml \
-e $CNF/fix-nova-reserved-host-memory.yaml \
--ntp-server 192.0.2.1
EOF
```

### 安装完成后检查 overcloud controller 的 /var/lib/ironic 目录
```

overcloud 
[heat-admin@overcloud-controller-0 ~]$ sudo ls /var/lib/ironic/
httpboot  tftpboot
[heat-admin@overcloud-controller-0 ~]$ sudo ls /var/lib/ironic/httpboot/
boot.ipxe

```

### 配置 overcloud 部署网络
```
source overcloudrc

创建部署网络
openstack network create \
  --provider-network-type flat \
  --provider-physical-network baremetal \
  --share provisioning

根据当前的实现，overcloud baremetal provisioning network/subnet 需要路由可达 overcloud ironic 的 api，overcloud ironic api 默认在 undercloud provisioning network 上，也就是 overcloud 的部署网络上。

在实验环境里，手工在 overcloud-controler-0 的 br-baremetal 上配置 192.0.3.250 这个 ip 地址，然后设置这个 ip 作为 subnet-provisioning 的网关，这样做的目的是让 overcloud baremetal 节点路由可达 overcloud ironic api。

openstack subnet create \
  --network provisioning \
  --subnet-range 192.0.3.0/24 \
  --ip-version 4 \
  --gateway 192.0.3.250 \
  --allocation-pool start=192.0.3.10,end=192.0.3.20 \
  --dhcp subnet-provisioning

创建 router
openstack router create router-provisioning

附加 subnet 到 router 
openstack router add subnet router-provisioning subnet-provisioning
```

### 配置 Overcloud Baremetal Node Cleaning 
```
添加如下内容到 templates/ironic.yaml
(overcloud) [stack@undercloud ~]$ cat >> templates/ironic.yaml <<EOF

  ############################
  #  Ironic Cleaning Network #
  ############################
  IronicCleaningNetwork: $(openstack network show provisioning -f value -c id)
EOF

重新执行 overcloud deploy 脚本 (未执行)
```

### 创建 baremetal flavor
```
source ~/overcloudrc
openstack flavor list
openstack flavor create \
  --id auto --ram 4096 \
  --vcpus 1 --disk 40 \
  --property baremetal=true \
  --public baremetal
```

### 创建 baremetal image
```
上传 deploy image

$ source overcloudrc

$ openstack image create \
  --container-format aki \
  --disk-format aki \
  --public \
  --file /var/lib/ironic/httpboot/agent.kernel bm-deploy-kernel

$ openstack image create \
  --container-format ari \
  --disk-format ari \
  --public \
  --file /var/lib/ironic/httpboot/agent.ramdisk bm-deploy-ramdisk

上传 user image
(overcloud) [stack@undercloud ~]$ cd images/
(overcloud) [stack@undercloud images]$ export DIB_LOCAL_IMAGE="rhel-8.2-x86_64-kvm.qcow2"

我的使用的环境是 osp 16.1 undercloud，操作系统是 rhel 8.2，软件仓库是 rhel 8.2 eus
因此使用的镜像是 rhel-8.2-x86_64-kvm.qcow2。
注意：软件仓库和镜像需要版本一致，才能避免依赖关系冲突问题

cat > local.repo <<EOF
[rhel-8-for-x86_64-baseos-eus-rpms]
name=rhel-8-for-x86_64-baseos-eus-rpms
baseurl=http://192.168.8.21:8787/repos/osp16.1/rhel-8-for-x86_64-baseos-eus-rpms/
enabled=1
gpgcheck=0

[rhel-8-for-x86_64-appstream-eus-rpms]
name=rhel-8-for-x86_64-appstream-eus-rpms
baseurl=http://192.168.8.21:8787/repos/osp16.1/rhel-8-for-x86_64-appstream-eus-rpms/
enabled=1
gpgcheck=0
EOF

export DIB_YUM_REPO_CONF="/home/stack/images/local.repo"
export DIB_LOCAL_IMAGE="rhel-8.2-x86_64-kvm.qcow2"
export DIB_RELEASE="8"
(overcloud) [stack@undercloud images]$ disk-image-create rhel baremetal -o rhel-image
...
2021-09-14 07:18:17.612 | INFO diskimage_builder.block_device.blockdevice [-] Getting value for [image-path]
2021-09-14 07:18:18.762 | INFO diskimage_builder.block_device.level3.mount [-] Called for [mount_mkfs_root]
2021-09-14 07:18:18.762 | INFO diskimage_builder.block_device.utils [-] Calling [sudo sync]
2021-09-14 07:18:18.854 | INFO diskimage_builder.block_device.utils [-] Calling [sudo fstrim --verbose /tmp/dib_build.AemYdmS5/mnt
/]
2021-09-14 07:18:18.980 | INFO diskimage_builder.block_device.utils [-] Calling [sudo umount /tmp/dib_build.AemYdmS5/mnt/]
2021-09-14 07:18:19.907 | INFO diskimage_builder.block_device.level0.localloop [-] loopdev detach
2021-09-14 07:18:19.907 | INFO diskimage_builder.block_device.utils [-] Calling [sudo losetup -d /dev/loop0]
2021-09-14 07:18:21.374 | INFO diskimage_builder.block_device.blockdevice [-] Removing temporary state dir [/tmp/dib_build.AemYdmS5/states/block-device]
2021-09-14 07:18:21.778 | Converting image using qemu-img convert
2021-09-14 07:21:12.524 | Image file rhel-image.qcow2 created...
2021-09-14 07:21:13.150 | Build completed successfully

(overcloud) [stack@undercloud images]$ ls -ltr
...
-rw-rw-r--. 1 stack stack        366 Sep 10 21:34 local.repo
-rw-r--r--. 1 root  root  1159135232 Sep 14 14:51 rhel-8.2-x86_64-kvm.qcow2
drwxrwxr-x. 3 stack stack         27 Sep 14 15:17 rhel-image.d
-rwxr-xr-x. 1 root  root     8924528 Sep 14 15:17 rhel-image.vmlinuz          <== baremetal image kernel
-rw-r--r--. 1 root  root    53965501 Sep 14 15:17 rhel-image.initrd           <== baremetal image initrd
-rw-r--r--. 1 stack stack  801494528 Sep 14 15:21 rhel-image.qcow2            <== baremetal whole user disk image


(overcloud) [stack@undercloud images]$ cat rhel-image.d/dib-manifests/dib_arguments 
rhel baremetal -o rhel-image

(overcloud) [stack@undercloud images]$ cat rhel-image.d/dib-manifests/dib_environment 
declare -x DIB_ARGS="rhel baremetal -o rhel-image"
declare -x DIB_LOCAL_IMAGE="rhel-8.2-x86_64-kvm.qcow2"
declare -x DIB_PYTHON_EXEC="/usr/libexec/platform-python"
declare -x DIB_RELEASE="8"
declare -x DIB_YUM_REPO_CONF="/home/stack/images/local.repo"


上传镜像
(overcloud) [stack@undercloud images]$ KERNEL_ID=$(openstack image create \
  --file rhel-image.vmlinuz --public \
  --container-format aki --disk-format aki \
  -f value -c id rhel-image.vmlinuz)
(overcloud) [stack@undercloud images]$ RAMDISK_ID=$(openstack image create \
  --file rhel-image.initrd --public \
  --container-format ari --disk-format ari \
  -f value -c id rhel-image.initrd)
(overcloud) [stack@undercloud images]$ openstack image create \
  --file rhel-image.qcow2   --public \
  --container-format bare \
  --disk-format qcow2 \
  --property kernel_id=$KERNEL_ID \
  --property ramdisk_id=$RAMDISK_ID \
  rhel-image

文档里的 5.5 部分可以省略
https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/16.2-beta/html/bare_metal_provisioning/configuring-the-bare-metal-provisioning-service-after-deployment#configuring-deploy-interfaces_bare-metal-post-deployment

生成节点的注册文件，这个节点对应 undercloud 的 overcloud-compute02
(overcloud) [stack@undercloud ~]$ cat instackenv-compute.json 
{
  "nodes": [
    {
      "mac": [
        "52:54:00:10:84:ab"
      ],
      "name": "overcloud-compute01",
      "pm_addr": "192.168.1.4",
      "pm_port": "623",
      "pm_password": "redhat",
      "pm_type": "pxe_ipmitool",
      "pm_user": "admin"
    },
    {
      "mac": [
        "52:54:00:ca:d7:a3"
      ],
      "name": "overcloud-compute02",
      "pm_addr": "192.168.1.5",
      "pm_port": "623",
      "pm_password": "redhat",
      "pm_type": "pxe_ipmitool",
      "pm_user": "admin"
    }
  ]
}

注意，在 overcloud 里注册节点时用的部署网卡和 undercloud 不同

cat > overcloud-nodes.yaml << EOF
nodes:
    - name: baremetal-node0
      driver: ipmi
      driver_info:
        ipmi_address: 192.168.1.5
        ipmi_port: "623"
        ipmi_username: admin
        ipmi_password: redhat
      properties:
        cpus: 4
        memory_mb: 12288
        local_gb: 40
      ports:
        - address: "52:54:00:a1:b7:7a"
EOF

生成 baremetal 节点
(overcloud) [stack@undercloud ~]$ openstack baremetal create overcloud-nodes.yaml
(overcloud) [stack@undercloud ~]$ openstack baremetal node list
+--------------------------------------+-----------------+---------------+-------------+--------------------+-------------+
| UUID                                 | Name            | Instance UUID | Power State | Provisioning State | Maintenance |
+--------------------------------------+-----------------+---------------+-------------+--------------------+-------------+
| cd01b1c5-d63b-4967-921f-f9fcc0322652 | baremetal-node0 | None          | None        | enroll             | False       |
+--------------------------------------+-----------------+---------------+-------------+--------------------+-------------+

5.6.4 设定 baremetal 节点对应的 deploy kernel 和 deploy initrd
(overcloud) [stack@undercloud ~]$ openstack baremetal node set $(openstack baremetal node show baremetal-node0 -f value -c uuid) \
  --driver-info deploy_kernel=$(openstack image show bm-deploy-kernel -f value -c id) \
  --driver-info deploy_ramdisk=$(openstack image show bm-deploy-ramdisk -f value -c id)

5.6.5 设定 baremetal 节点的 Provisioning State 为 available
(overcloud) [stack@undercloud ~]$ openstack baremetal node manage $(openstack baremetal node show baremetal-node0 -f value -c uuid)
(overcloud) [stack@undercloud ~]$ openstack baremetal node provide $(openstack baremetal node show baremetal-node0 -f value -c uuid)

注意：libvirt 下需手工配置网卡支持 PXE 启动

出错后执行
(overcloud) [stack@undercloud ~]$ openstack baremetal node maintenance unset $(openstack baremetal node show baremetal-node0 -f value -c uuid)
(overcloud) [stack@undercloud ~]$ openstack baremetal node manage $(openstack baremetal node show baremetal-node0 -f value -c uuid)
(overcloud) [stack@undercloud ~]$ openstack baremetal node provide $(openstack baremetal node show baremetal-node0 -f value -c uuid)

overcloud baremeatl 的 provisioning 网络需要能路由到 undercloud provisioning 网路
# virsh net-list
 Name                 State      Autostart     Persistent
----------------------------------------------------------
 crc                  active     yes           yes
 default              active     yes           yes
 oc-provisioning      active     yes           yes         <== 这个网络需要路由到 provisioning
 openshift4           active     yes           yes
 openshift4a          active     no            no
 openshift4v6         active     yes           yes
 provisioning         active     yes           yes         <== 这个网络需要路由到 oc-provisioning

定义可路由的虚拟网络
https://jamielinux.com/docs/libvirt-networking-handbook/routed-network.html
# virsh net-dumpxml provisioning 
<network>
  <name>provisioning</name>
  <uuid>79803491-ce42-47c1-ad53-638927b9fc04</uuid>
  <forward mode='route'/>                                  <== 注意这行
  <bridge name='virbr1' stp='on' delay='0'/>
  <mac address='52:54:00:f1:fb:a3'/>
  <ip address='192.0.2.254' netmask='255.255.255.0'>
  </ip>
</network>

# virsh net-dumpxml oc-provisioning 
<network>
  <name>oc-provisioning</name>
  <uuid>052217fa-5085-476f-b2f7-8aca84952d29</uuid>
  <forward mode='route'/>                                  <== 注意这行
  <bridge name='virbr2' stp='on' delay='0'/>
  <mac address='52:54:00:f0:2a:5f'/>
  <ip address='192.0.3.254' netmask='255.255.255.0'>
  </ip>
</network>

重启虚拟网络
virsh net-destroy provisioning
virsh net-start provisioning

virsh net-destroy oc-provisioning
virsh net-start oc-provisioning

在系统里设置路由
ip route delete 192.0.2.0/24                                <== 删除 libvirt 创建的默认路由
ip route add 192.0.2.0/24 via 192.0.2.254
ip route delete 192.0.3.0/24                                <== 删除 libvirt 创建的默认路由
ip route add 192.0.3.0/24 via 192.0.3.254


参考链接
https://www.ibm.com/docs/zh-tw/urbancode-deploy/6.2.1?topic=coobc-using-dedicated-environment-create-chef-compatible-images-openstack-based-clouds
```

### 参考文档
https://docs.openstack.org/project-deploy-guide/tripleo-docs/latest/features/baremetal_overcloud.html