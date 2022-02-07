### Restful API
```
username="admin"
password="JVB3JSoTM24jqrervIJ707NQ0"
projectname="admin"
publicapi="192.168.122.18"

echo "GET TOKEN"
curl -i \
  -H "Content-Type: application/json" \
  -d "
{ \"auth\": {
    \"identity\": {
      \"methods\": [\"password\"],
      \"password\": {
        \"user\": {
          \"name\": \"$username\",
          \"domain\": { \"id\": \"default\" },
          \"password\": \"$password\"
        }
      }
    },
    \"scope\": {
      \"project\": {
        \"name\": \"admin\",
        \"domain\": { \"id\": \"default\" }
      }
    }
  }
}" \
http://${publicapi}:5000/v3/auth/tokens 2>&1 | tee /tmp/tempfile

token=$(cat /tmp/tempfile | awk '/X-Subject-Token: /{print $NF}' | tr -d '\r' )
echo $token
export mytoken=$token

echo "GETTING IMAGES"
imageid=$(curl -s \
--header "X-Auth-Token: $mytoken" \
 http://${publicapi}:9292/v2/images | jq '.images[] | select(.name=="cirros")' | jq -r '.id' )

echo "GETTING FLAVOR"
flavorid=$(curl -s \
--header "X-Auth-Token: $mytoken" \
http://${publicapi}:8774/v2.1/flavors | jq '.flavors[] | select(.name=="m1.nano")' | jq -r '.id' ) 

echo "GET NETWORK"
networkid=$(curl -s \
-H "Accept: application/json" \
-H "X-Auth-Token: $mytoken" \
http://${publicapi}:9696/v2.0/networks | jq '.networks[] | select(.name=="private")' | jq -r '.id' )

echo "CREATE SERVER"
curl -g -i -X POST http://${publicapi}:8774/v2.1/servers \
-H "Accept: application/json" \
-H "Content-Type: application/json" \
-H "X-Auth-Token: $mytoken" -d "{\"server\": {\"name\": \"test-instance\", \"imageRef\": \"$imageid\", \"flavorRef\": \"$flavorid\", \"min_count\": 1, \"max_count\": 1, \"networks\": [{\"uuid\": \"$networkid\"}]}}"

echo "GET INSTANCEID"
instanceid=$(curl -s \
-H "Accept: application/json" \
--header "X-Auth-Token: $mytoken" \
-X GET http://${publicapi}:8774/v2.1/servers | jq '.servers[] | select(.name=="test-instance")' | jq -r '.id' )

echo "DELETE INSTANCE"
curl -g -i -X DELETE http://${publicapi}:8774/v2.1/servers/$instanceid \
-H "Accept: application/json" \
-H "Content-Type: application/json" \
-H "X-Auth-Token: $mytoken" 
```

### Grafana Dashboard 相关的信息
https://izsk.me/2019/09/07/%E5%9C%A8Grafana%E4%B8%AD%E7%BB%9F%E8%AE%A1%E7%89%A9%E7%90%86%E6%9C%BA%E4%B8%8A%E5%AE%B9%E5%99%A8%E7%8A%B6%E6%80%81%E5%88%86%E7%B1%BB%E6%B1%87%E6%80%BB/<br>
https://www.jianshu.com/p/7e7e0d06709b
```
  "targets": [
    {
      "exemplar": true,
      "expr": "sum by (resource, plugin_instance) (label_replace(collectd_virt_memory{service=~\".+-$clouds-.+\"}, \"resource\", \"$1\", \"host\", \"(.+):.+\")) + on(resource) group_right(plugin_instance) ceilometer_cpu{project=\"$projects\", service=~\".+-$clouds-.+\"}",
      "instant": true,
      "interval": "",
      "legendFormat": "{{plugin_instance}}",
      "refId": "A"
    }
  ],


"expr": "sum by (resource, plugin_instance) (label_replace(collectd_virt_memory, \"resource\", \"$1\", \"host\", \".+:(.+):.+\")) + on(resource) group_right(plugin_instance) ceilometer_cpu{project=\"$projects\"}",



sum by (resource, plugin_instance) (label_replace(collectd_virt_memory{service=~\".+-$clouds-.+\"}, \"resource\", \"$1\", \"host\", \".+:(.+):.+\")) + on(resource) group_right(plugin_instance) ceilometer_cpu{project=\"573de9f1520b4e08852cb5e17e734ede\", service=~\".+-cloud1-.+\"}


sum by (resource, plugin_instance) (label_replace(collectd_virt_memory{service=~".+-cloud1-.+"}, "resource", "$1", "host", ".+:(.+):.+")) + on(resource) group_right(plugin_instance) ceilometer_cpu{project="573de9f1520b4e08852cb5e17e73e",service=~".+-cloud1-.+"}

sum by (resource, plugin_instance) (label_replace(collectd_virt_memory{service=~".+-cloud1-.+"}, "resource", "$1", "host", ".+-.+")) + on(resource) group_right(plugin_instance) ceilometer_cpu{project="573de9f1520b4e08852cb5e17e73e"}
```

### 使用 Elasticsearch Operator 快速部署 Elasticsearch 集群
https://www.qikqiak.com/post/elastic-cloud-on-k8s/
```
# 在 STF 1.3 下创建 kibana 资源
apiVersion: kibana.k8s.elastic.co/v1
kind: Kibana
metadata:
  name: kibana
  namespace: service-telemetry
spec:
  version: 7.10.2
  nodeCount: 1
  elasticsearchRef:
    name: elasticsearch

# 注意 version: 7.10.2 与 elasticsearch 的版本一致

oc get secret
...
kibana-kb-config                                Opaque                                2      17h
kibana-kb-es-ca                                 Opaque                                2      17h
kibana-kb-http-ca-internal                      Opaque                                2      17h
kibana-kb-http-certs-internal                   Opaque                                3      17h
kibana-kb-http-certs-public                     Opaque                                2      17h
kibana-kibana-user                              Opaque                                1      17h

# TLS certification
https://www.elastic.co/guide/en/cloud-on-k8s/master/k8s-tls-certificates.html

oc run curl --image=radial/busyboxplus:curl -i --tty
curl -v -k https://kibana-kb-http:5601

cd ~/tmp
oc create route passthrough kibana-kb-route --service=kibana-kb-http --port=5601 

oc get secret elasticsearch-es-elastic-user -o jsonpath='{.data.elastic}' | base64 --decode
a16O5gq448IhL91G1GvbbQ2D
```

### 当 chrome 打开页面显示报错信息 '该网站发回了异常的错误凭据' 的处理方法
如果确认网址是正确的，可以在页面输入 'thisisunsafe'

### 计划让 STF 1.3 支持 OCP 4.8
https://github.com/infrawatch/service-telemetry-operator/pull/277

### OSP: Failure prepping block device., Code: 500 when deploying whole disk secure image
https://bugzilla.redhat.com/show_bug.cgi?id=1668858

### Encryption at Rest - Red Hat Ceph Storage 5
https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html/data_security_and_hardening_guide/assembly-encryption-and-key-management

### OpenStack VaultLocker
https://github.com/openstack-charmers/vaultlocker<br>
关于在 Hashicorp Vault 中存储 LUKS dm-crypt 加密 keys

Linux Unified Key Setup
https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup<br>

### 如何配置 ceph rgw multisite
https://medium.com/@avmor/how-to-configure-rgw-multisite-in-ceph-65e89a075c1f

### Pulling a docker image hosted by Satellite throws 403 error or digest verification failed error
https://access.redhat.com/solutions/3363761

### Ceph 参考架构 Cisco UCS and red hat ceph storage 4
https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/UCS_CVDs/ucs_c240m5_redhatceph4.html?dtid=osscdc000283<br>
https://blog.csdn.net/swingwang/article/details/60781084<br>
https://dnsflagday.net/2020/<br>

### osp 16.1 pre-provisioned nodes templatess
https://gitlab.cee.redhat.com/sputhenp/lab/-/tree/master/templates/osp-16-1/pre-provisioned

### Enrich your Ceph Object Storage Data Lake by leveraging Kafka as the Data Source
用 Kafka 作为胶水将数据源和 Data Lake 以及数据分析解决方案粘在一起<br>
https://itnext.io/enrich-your-ceph-object-storage-data-lake-by-leveraging-kafka-as-the-data-source-e9a4d305abcf

### RBD snapshot 是否支持 crash consistency 文档
https://github.com/ceph/ceph/pull/43764

### STF 集成
https://bugzilla.redhat.com/show_bug.cgi?id=1845943

### The future of data engineer
https://aws.amazon.com/big-data/datalakes-and-analytics/data-lake-house/

https://netflixtechblog.com/optimizing-data-warehouse-storage-7b94a48fdcbe

https://github.com/sripathikrishnan/jinjasql

https://preset.io/blog/the-future-of-the-data-engineer/

https://www.montecarlodata.com/the-future-of-the-data-engineer/

### Error
```
sudo cat /var/lib/mistral/overcloud/ansible.log | grep -E "fatal:" -A60
...
        "<13>Nov  2 10:30:35 puppet-user: Error: /Stage[main]/Tripleo::Certmonger::Neutron/Certmonger_certificate[neutron]: Could not evaluate: Could not get certificate: Server at https://helper.example.com/ipa/xml denied our request, giving up: 2100 (RPC failed at server.  Insufficient access: Insufficient 'add' privilege to add the entry 'krbprincipalname=neutron/overcloud-controller-0.internalapi.example.com@EXAMPLE.COM,cn=services,cn=accounts,dc=example,dc=com'.).",
(undercloud) [stack@undercloud ~]$ cat install-undercloud.log | grep "fatal:"  | more
...
File \"/usr/lib/python3.6/site-packages/keystoneauth1/identity/base.py\", line 134, in get_access\n    self.auth_ref = self.ge
t_auth_ref(session)\n  File \"/usr/lib/python3.6/site-packages/keystoneauth1/identity/generic/base.py\", line 206, in get_auth_ref\n    self._plug
in = self._do_create_plugin(session)\n  File \"/usr/lib/python3.6/site-packages/keystoneauth1/identity/generic/base.py\", line 161, in _do_create_
plugin\n    'auth_url is correct. %s' % e)\nkeystoneauth1.exceptions.discovery.DiscoveryFailure: Could not find versioned identity endpoints when 
attempting to authenticate. Please check that your auth_url is correct. SSL exception connecting to https://192.0.2.2:13000: HTTPSConnectionPool(h
ost='192.0.2.2', port=13000): Max retries exceeded with url: / (Caused by SSLError(SSLError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verif
y failed (_ssl.c:897)'),))\n", "module_stdout": "", "msg": "MODULE FAILURE\nSee stdout/stderr for the exact error", "rc": 1}


```

### Deploying OpenShift 4.x on non-tested platforms using the bare metal install method
https://access.redhat.com/articles/4207611


### 调试
```
virsh attach-disk jwang-rhel82-undercloud /root/jwang/isos/rhel-8.2-x86_64-dvd.iso hda --type cdrom --mode readonly --config
# ks=http://10.66.208.115/jwang-rhel82-undercloud-ks.cfg nameserver=192.168.8.1 ip=192.168.8.21::192.168.8.1:255.255.255.0:undercloud.example.com:ens3:none

# 生成 ks.cfg - jwang-rhel82-undercloud
cat > jwang-rhel82-undercloud-ks.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart --nohome
network --device=ens3 --hostname=undercloud.example.com --bootproto=static --ip=192.168.8.21 --netmask=255.255.255.0 --gateway=192.168.8.1 --nameserver=192.168.8.1
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
%end
EOF

virsh attach-disk jwang-helper-undercloud /root/jwang/isos/rhel-8.2-x86_64-dvd.iso hda --type cdrom --mode readonly --config
# ks=http://10.66.208.115/jwang-helper-undercloud-ks.cfg nameserver=192.168.8.1 ip=192.168.8.22::192.168.8.1:255.255.255.0:helper.example.com:ens3:none

# 生成 ks.cfg - jwang-helper-undercloud
cat > jwang-helper-undercloud-ks.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart
network --device=ens3 --hostname=helper.example.com --bootproto=static --ip=192.168.8.22 --netmask=255.255.255.0 --gateway=192.168.8.1 --nameserver=192.168.8.1
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
%end
EOF

for i in rhel-8-for-x86_64-baseos-eus-rpms rhel-8-for-x86_64-appstream-eus-rpms rhel-8-for-x86_64-highavailability-eus-rpms ansible-2.9-for-rhel-8-x86_64-rpms openstack-16.1-for-rhel-8-x86_64-rpms fast-datapath-for-rhel-8-x86_64-rpms rhceph-4-tools-for-rhel-8-x86_64-rpms advanced-virt-for-rhel-8-x86_64-rpms
do
cat >> /etc/yum.repos.d/osp.repo << EOF
[$i]
name=$i
baseurl=file:///var/www/html/repos/osp16.1/$i/
enabled=1
gpgcheck=0

EOF
done


cat > ~/templates/node-info.yaml << 'EOF'
parameter_defaults:
  ControllerCount: 3
  ComputeCount: 0
  ComputeHCICount: 3

  # SchedulerHints
  ControllerSchedulerHints:
    'capabilities:node': 'controller-%index%'
  ComputeSchedulerHints:
    'capabilities:node': 'compute-%index%'
  ComputeHCISchedulerHints:
    'capabilities:node': 'computehci-%index%'
EOF


(undercloud) [stack@undercloud ~]$ cat > ~/deploy-enable-tls-octavia-stf.sh << 'EOF'
#!/bin/bash
THT=/usr/share/openstack-tripleo-heat-templates/
CNF=~/templates/

source ~/stackrc
openstack overcloud deploy --debug --templates $THT \
-r $CNF/roles_data.yaml \
-n $CNF/network_data.yaml \
-e $THT/environments/ceph-ansible/ceph-ansible.yaml \
-e $THT/environments/ceph-ansible/ceph-rgw.yaml \
-e $THT/environments/ssl/enable-internal-tls.yaml \
-e $THT/environments/ssl/tls-everywhere-endpoints-dns.yaml \
-e $THT/environments/network-isolation.yaml \
-e $CNF/environments/network-environment.yaml \
-e $CNF/environments/fixed-ips.yaml \
-e $CNF/environments/net-bond-with-vlans.yaml \
-e $THT/environments/services/octavia.yaml \
-e $THT/environments/metrics/ceilometer-write-qdr.yaml \
-e $THT/environments/metrics/collectd-write-qdr.yaml \
-e $THT/environments/metrics/qdr-edge-only.yaml \
-e ~/containers-prepare-parameter.yaml \
-e $CNF/custom-domain.yaml \
-e $CNF/node-info.yaml \
-e $CNF/enable-tls.yaml \
-e $CNF/inject-trust-anchor.yaml \
-e $CNF/keystone_domain_specific_ldap_backend.yaml \
-e $CNF/cephstorage.yaml \
-e $CNF/fix-nova-reserved-host-memory.yaml \
-e $CNF/enable-stf.yaml \
-e $CNF/stf-connectors.yaml \
--ntp-server 192.0.2.1
EOF
```

### openshift container storage labs
https://access.redhat.com/labs/ocssi/<br>

### OpenShift 与 Global Load Balancer
https://cloud.redhat.com/blog/global-load-balancer-for-openshift-clusters-an-operator-based-approach<br>

### 有状态应用与双数据中心的难题
https://cloud.redhat.com/blog/stateful-workloads-and-the-two-data-center-conundrum

### Disaster Recovery Strategies for Applications Running on OpenShift
https://cloud.redhat.com/blog/disaster-recovery-strategies-for-applications-running-on-openshift

```
cat > /tmp/inventory <<EOF
[controller]
192.0.2.5[1:3] ansible_user=heat-admin ansible_become=yes ansible_become_method=sudo

[computehci]
192.0.2.7[1:3] ansible_user=heat-admin ansible_become=yes ansible_become_method=sudo

EOF

(undercloud) [stack@undercloud ~]$ ansible -i /tmp/inventory all -m copy -a 'src=/tmp/10-cephdest=/etc/pki/ca-trust/source/anchors'

```

### ODH OCP 4.9
```
报错信息
csv created in namespace with multiple operatorgroups, can't pick one automatically

解决方法：创建 opendatahub namespace，在 opendatahub namespace 下创建 opendatahub 资源

报错信息
constraints not satisfiable: subscription seldon-operator-certified exists, no operators found in package seldon-operator-certified in the catalog referenced by subscription seldon-operator-certified

podman cp 的例子
https://github.com/containers/podman/blob/main/docs/source/markdown/podman-cp.1.md
```

### Ceph 与中心 prometheus 的集成
https://bugzilla.redhat.com/show_bug.cgi?id=1897250<br>
https://github.com/ceph/ceph/blob/master/src/mgr/DaemonHealthMetricCollector.cc#L33-L56<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1259160<br>
https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html-single/dashboard_guide/index#network-port-requirements-for-ceph-dashboard_dash<br>
https://gitlab.consulting.redhat.com/iberia-consulting/inditex/ceph/cer-rhcs4-archive-zone<br>
https://github.com/prometheus/snmp_exporter<br>
https://gitlab.consulting.redhat.com/iberia-consulting/inditex/ceph/upgrade-rhcs4<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1902212<br>
https://documentation.suse.com/ses/7/html/ses-all/monitoring-alerting.html#prometheus-webhook-snmp<br>
https://github.com/SUSE/prometheus-webhook-snmp<br>
https://prometheus.io/docs/alerting/latest/alertmanager/#high-availability<br>
https://grafana.com/docs/grafana/latest/administration/set-up-for-high-availability<br>
https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/4/html-single/installation_guide/index#colocation-of-containerized-ceph-daemons<br>
https://access.redhat.com/articles/1548993<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1831995<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1831995#c38<br>
https://fossies.org/linux/collectd/src/collectd.conf.in<br>

### 如何调试 ROOK
设置 ROOK_LOG_LEVEL=DEBUG 

### OSP 16.2 备份与恢复
https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/16.2/html-single/backing_up_and_restoring_the_undercloud_and_control_plane_nodes/index<br>
https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/16.2/html-single/back_up_and_restore_the_director_undercloud/index<br>

https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/16.1/html-single/operational_measurements/index<br>


```
# https://bugzilla.redhat.com/show_bug.cgi?id=1594967
2021-11-08 03:12:57.558 77 WARNING neutron.pecan_wsgi.controllers.root [req-7e952a16-ad2c-47d5-8b12-c8b7f5720d3d 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: fw - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:01.439 76 WARNING neutron.pecan_wsgi.controllers.root [req-52b36b8d-c615-43ca-ada4-51841a77c3c7 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: fw - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:15.700 76 WARNING neutron.pecan_wsgi.controllers.root [req-d9f5ad06-fd2d-4536-986d-65cd6869fca4 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: vpn - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:21.063 76 WARNING neutron.pecan_wsgi.controllers.root [req-2b5aa5c6-3b73-498a-aee6-baad8ed7d3e0 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: vpn - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:24.775 77 WARNING neutron.pecan_wsgi.controllers.root [req-5697a4a7-194f-4e09-85be-cc146ef503ff 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: lbaas - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:25.227 76 WARNING neutron.pecan_wsgi.controllers.root [req-12929c75-2462-436b-9e89-f497c3fb03ad 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: lbaas - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:25.627 77 WARNING neutron.pecan_wsgi.controllers.root [req-acd8ac0e-fd6b-4457-ad78-0ba02737dde0 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: fw - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:26.202 77 WARNING neutron.pecan_wsgi.controllers.root [req-34e17998-17c2-4756-adba-b154bdb49341 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: vpn - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:26.534 76 WARNING neutron.pecan_wsgi.controllers.root [req-b9223895-0183-4651-b344-130b107b782d 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: lbaas - returning response code 404: pecan.routing.PecanNotFound
2021-11-08 03:13:27.794 76 WARNING neutron.pecan_wsgi.controllers.root [req-c2714d95-1582-4ae5-8c91-6284521055bc 4b7041bb93c0438e921c8d6e1516a2d9 5a7854f1b7ea41169141436b1c5bf02c - default default] No controller found for: lbaas - returning response code 404: pecan.routing.PecanNotFound

openstack.exceptions.HttpException: HttpException: 502: Server Error for url: https://overcloud.example.com:13696/v2.0/agents, Reason: Error reading from remote server: response from an upstream server.: The proxy server received an invalid: 502 Proxy Error: The proxy server could not handle the request GET&nbsp;/v2.0/agents.: Proxy Error


WARNING ceilometer.neutron_client [-] The resource could not be found.:neutronclient.common.exceptions.NotFound: The resource could not be found.

Nov 09 13:55:53 base-pvg.redhat.ren libvirtd[21062]: 2021-11-09 05:55:53.711+0000: 21062: error : virNetSocketReadWire:1806 : 读Hint: Some lines were ellipsized, use -l to show in full.

```

### CentOS Stream 的 EPEL 是 EPEL Next
https://fedoraproject.org/wiki/EPEL_Next

### OSP 16.1 与 collectd 
```
osp 16.1 安装的 collectd 版本

collectd-5.11.0-5.el8ost.x86_64
```

### 下载软件包及依赖
https://ostechnix.com/download-rpm-package-dependencies-centos/<br>
https://access.redhat.com/solutions/10154<br>
```
yum install --downloadonly --downloaddir=<downloaddir> <package>
```

### 为 osp collectd 容器添加 rrd plugins
```
> /tmp/osp.repo

for i in rhel-8-for-x86_64-baseos-eus-rpms rhel-8-for-x86_64-appstream-eus-rpms rhel-8-for-x86_64-highavailability-eus-rpms ansible-2.9-for-rhel-8-x86_64-rpms openstack-16.1-for-rhel-8-x86_64-rpms fast-datapath-for-rhel-8-x86_64-rpms rhceph-4-tools-for-rhel-8-x86_64-rpms advanced-virt-for-rhel-8-x86_64-rpms
do 
cat >> /tmp/osp.repo <<EOF
[$i]
name=$i
baseurl=http://192.0.2.1:8088/repos/osp16.1/$i/
enabled=1
gpgcheck=0

EOF
done

# 拷贝 osp.repo
cat > /tmp/inventory <<EOF
[controller]
192.0.2.5[1:3] ansible_user=heat-admin ansible_become=yes ansible_become_method=sudo

[computehci]
192.0.2.7[1:3] ansible_user=heat-admin ansible_become=yes ansible_become_method=sudo

EOF

(undercloud) [stack@undercloud ~]$ ansible -i /tmp/inventory all -m copy -a 'src=/tmp/osp.repo dest=/etc/yum.repos.d'

# 在 overcloud 节点上，挂在 collectd pod 到 host
[heat-admin@overcloud-controller-0 ~]$
sudo -i 
podman ps | grep collectd 
mnt=$(podman mount $(podman ps | grep collectd | awk '{print $1}') )

# 拷贝 /etc/yum.repos.d/osp.repo 到容器内
cp /etc/yum.repos.d/osp.repo $mnt/etc/yum.repos.d

# 为容器内安装 rrdtool
yum install --installroot=$mnt rrdtool

# 拷贝 collectd-rrdtool 软件包到容器内
cp /tmp/collectd-rrdtool-5.11.0-9.el8ost.x86_64.rpm $mnt/tmp

# 切换到容器内，安装 collectd rrdtool 插件
podman exec -it collectd sh
()[root@overcloud-controller-0 /]$ rpm -ivh /tmp/collectd-rrdtool-5.11.0-9.el8ost.x86_64.rpm --force
()[root@overcloud-controller-0 /]$ exit

# 生成 collectd rrdtool 插件配置文件
[heat-admin@overcloud-controller-0 ~]$
sudo -i
cd /var/lib/config-data/puppet-generated/collectd/etc/collectd.d
# https://frontier.town/2017/10/collectd-and-rrdtool/
cat > 10-rrdtool.conf <<EOF
LoadPlugin rrdtool
<Plugin rrdtool>
	DataDir "/var/lib/collectd/rrd"
	CreateFilesAsync false
	CacheTimeout 120
	CacheFlush   900
	WritesPerSecond 50

	# The default settings are optimised for plotting time-series graphs over pre-fixed
  # time period, but are not very helpful for simply asking "what is my average memory
  # usage for the last hour?", so we define some new ones.

	# The first one is an anomaly, as it seems that the rrd plugin enforces some
	# minimums. The result is a time-series 200 hours long with a granularity of 10s.
	RRATimeSpan 3600
	# This defines a time-series 20 hours long with a granularity of 1 minute.
	RRATimeSpan 72000
	# This defines a time-series 50 days long with a granularity of 1 hour.
	RRATimeSpan 4320000
</Plugin>
EOF

# 重启 collectd 容器
podman restart collectd

# 检查 collectd 内 rrd 目录下的内容
podman exec -it collectd sh
()[root@overcloud-controller-0 /]$ ls /var/lib/collectd/rrd/overcloud-controller-0.example.com/
ceph-ceph-mon.overcloud-controller-0       libpodstats-ceph-mgr-overcloud-controller-0       libpodstats-nova_scheduler
cpu-0                                      libpodstats-ceph-mon-overcloud-controller-0       libpodstats-nova_vnc_proxy
cpu-1                                      libpodstats-ceph-rgw-overcloud-controller-0-rgw0  libpodstats-octavia_api
cpu-2                                      libpodstats-cinder_api                            libpodstats-octavia_driver_agent
cpu-3                                      libpodstats-cinder_api_cron                       libpodstats-octavia_health_manager
df-overlay                                 libpodstats-cinder_scheduler                      libpodstats-octavia_housekeeping
df-shm                                     libpodstats-clustercheck                          libpodstats-octavia_worker
df-tmpfs                                   libpodstats-collectd                              libpodstats-ovn_controller
disk-vda                                   libpodstats-galera-bundle-podman-0                libpodstats-ovn-dbs-bundle-podman-0
disk-vda1                                  libpodstats-glance_api                            libpodstats-placement_api
disk-vda2                                  libpodstats-glance_api_tls_proxy                  libpodstats-rabbitmq-bundle-podman-0
hugepages-mm-2048Kb                        libpodstats-haproxy-bundle-podman-0               libpodstats-redis-bundle-podman-0
hugepages-node0-2048Kb                     libpodstats-heat_api                              libpodstats-redis_tls_proxy
interface-br-ex                            libpodstats-heat_api_cfn                          load
interface-br-int                           libpodstats-heat_api_cron                         memcached-local
interface-ens3                             libpodstats-heat_engine                           memory
interface-ens4                             libpodstats-horizon                               processes
interface-ens5                             libpodstats-iscsid                                uptime
interface-genev_sys_6081                   libpodstats-keystone                              vmem
interface-lo                               libpodstats-logrotate_crond                       vmem-direct
interface-o-hm0                            libpodstats-memcached                             vmem-dma
interface-ovs-system                       libpodstats-metrics_qdr                           vmem-dma32
interface-vlan20                           libpodstats-neutron_api                           vmem-kswapd
interface-vlan30                           libpodstats-neutron_server_tls_proxy              vmem-movable
interface-vlan40                           libpodstats-nova_api                              vmem-normal
interface-vlan50                           libpodstats-nova_api_cron                         vmem-throttle
libpodstats-ceilometer_agent_central       libpodstats-nova_conductor
libpodstats-ceilometer_agent_notification  libpodstats-nova_metadata

# 检查 collectd 内 rrd 目录下的 ceph 指标
()[root@overcloud-controller-0 /]$ ls /var/lib/collectd/rrd/overcloud-controller-0.example.com/ceph-ceph-mon.overcloud-controller-0 -1F | grep -Ei pg
ceph_bytes-Cluster.numPgActiveClean.rrd
ceph_bytes-Cluster.numPgActive.rrd
ceph_bytes-Cluster.numPgPeering.rrd
ceph_bytes-Cluster.numPg.rrd
ceph_bytes-Mempool.osdPglogBytes.rrd
ceph_bytes-Mempool.osdPglogItems.rrd
ceph_bytes-Mempool.pgmapBytes.rrd
ceph_bytes-Mempool.pgmapItems.rrd

```


### Ceph 监控
collectd + Graphite + Grafana
https://www.cnblogs.com/William-Guozi/p/grafana-monitor.html<br>

Grafana Ceph Cluster Dashboard，数据源来自 Prometheus
https://grafana.com/grafana/dashboards/2842<br>

Ceph Mgr Prometheus 模块
https://docs.ceph.com/en/latest/mgr/prometheus/<br>

### Ceph and OpenCAS
https://01.org/blogs/tingjie/2020/research-performance-tuning-hdd-based-ceph-cluster-using-open-cas

### DevOps 文化与实践
https://www.redhat.com/en/blog/devops-culture-and-practice-openshift-experience-driven-real-world-guide-building-empowered-teams<br>
https://www.redhat.com/en/engage/devops-culture-practice-openshift-ebooks<br>
https://www.whsmith.co.uk/products/adaptive-systems-with-domaindriven-design-wardley-maps-and-team-topologies-designing-architecture-fo/susanne-kaiser/paperback/9780137393039.html<br>
https://www.ready-to-innovate.com/<br>
https://github.com/boogiespook/rti/issues<br>
https://www.redhat.com/rhdc/managed-files/rh-slowing-down-digital-transformation-questions-ebook-f29635-202109-en_0.pdf<br>
https://voltagecontrol.com/blog/episode-60-a-future-forward-in-devops/<br>
https://www.linkedin.com/posts/andreasspanner_transformation-agile-changemanagement-activity-6836651389054263296-vtvs<br>
https://www.redhat.com/en/events/webinar/transformation-takes-practice-users-guide-open-practice-library<br>

### OSP 16.1 为 overcloud 添加 Red Hat Ceph Storage Dashboard
https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/16.1/html-single/deploying_an_overcloud_with_containerized_red_hat_ceph/index#adding-ceph-dashboard<br>

```
I wrote up a summary of this year's State of DevOps report on my blog over here: https://www.tomgeraghty.co.uk/index.php/the-state-of-devops-report-2021-a-summary/

https://access.redhat.com/solutions/5464941
Stderr: 'iscsiadm: Cannot perform discovery. Invalid Initiatorname.\niscsiadm: Could not perform SendTargets discovery: invalid parameter\n'
https://bugzilla.redhat.com/show_bug.cgi?id=1764187

sudo iptables -I INPUT 8 -p tcp -m multiport --dports 3260 -m state --state NEW -m comment --comment "100 iscsid ipv4" -j ACCEPT

# 检查最新文件的最后 10 行
ls -ltr | tail -1 | awk '{print $9}' | xargs cat | tail -10
watch -n5 "ls -ltr | tail -1 | awk '{print \$9}' | xargs cat | tail -10"
watch -n5 "sudo cd /var/log/containers/mistral && sudo ls -ltr | tail -1 | awk '{print \$9}' | sudo xargs cat | tail -10"
watch -n5 "sudo cd /var/log/containers/heat && sudo ls -ltr | tail -1 | awk '{print \$9}' | sudo xargs cat | tail -10"


# 部署失败，报错信息是
rhosp-rhel8/openstack-collectd:16.1'] run failed after + mkdir -p /etc/puppet

"<13>Nov  9 09:39:29 puppet-user: Error: Evaluation Error: Error while evaluating a Resource Statement, Evaluation Error: Error while evaluating a Resource Statement, Duplicate declaration: Tripleo::Profile::Base::Metrics::Collectd::Collectd_plugin[ceph] is already declared at (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp, line: 8); cannot redeclare (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp, line: 8) (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp, line: 8, column: 5) (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd.pp, line: 301) on node overcloud-computehci-0.example.com",

Tripleo::Profile::Base::Metrics::Collectd::Collectd_plugin[ceph]
/etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp
/etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp
/etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp
/etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd.pp

# 在所有 computehci 节点执行
sudo sed -i 's|^|#|g' /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp

Nov 10 03:44:30 overcloud-computehci-0.example.com puppet-user[19587]: Error: Evaluation Error: Error while evaluating a Resource Statement, Evaluation Error: Error while evaluating a Resource Statement, Duplicate declaration: Tripleo::Profile::Base::Metrics::Collectd::Collectd_plugin[ceph] is already declared at (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp, line: 8); cannot redeclare (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp, line: 8) (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd/collectd_service.pp, line: 8, column: 5) (file: /etc/puppet/modules/tripleo/manifests/profile/base/metrics/collectd.pp, line: 301) on node overcloud-computehci-0.example.com

https://bugzilla.redhat.com/show_bug.cgi?id=1845943


sudo iptables -I INPUT 8 -p tcp -m multiport --dports 5900:5999 -m state --state NEW -m comment --comment "100 vnc ipv4" -j ACCEPT

# Grafana 与 ceph mgr 容器
[heat-admin@overcloud-controller-0 ~]$ sudo podman ps | grep -E "mgr|grafana" 
072ab17f2678  undercloud.ctlplane.example.com:8787/rhceph/rhceph-4-dashboard-rhel8:4                                         2 hours ago        Up 2 hours ago               grafana-server
7b1f33ae193f  undercloud.ctlplane.example.com:8787/rhceph/rhceph-4-rhel8:latest                                              20 hours ago       Up 20 hours ago              ceph-mgr-overcloud-controller-0
```

### ODH 1.1.0 kfdef
https://github.com/opendatahub-io/odh-manifests/tree/v1.1.0/kfdef

### OpenShift Cluster 安装 CephFS csi
https://www.jianshu.com/p/5cbe9f58dda7

### 如何改变 Grafana password in director
[rhos-tech] [ceph-dashboard] How to change the Grafana password in director deployed ceph

### temp cmd 
```
cat > /tmp/inventory <<EOF
[controller]
192.0.2.51 ansible_user=root

[compute]
192.0.2.52 ansible_user=root

EOF

cat > /tmp/inventory <<EOF
[controller]
192.0.2.51 ansible_user=stack ansible_become=yes ansible_become_method=sudo

[compute]
192.0.2.52 ansible_user=stack ansible_become=yes ansible_become_method=sudo

EOF

报错
[ERROR] WSREP: wsrep::connect(gcomm://overcloud-controller-0.internalapi.localdomain,overcloud-controller-1.internalapi.localdomain,overcloud-controller-2.internalapi.localdomain) failed: 7

https://access.redhat.com/solutions/2085773

https://docs.openstack.org/project-deploy-guide/tripleo-docs/latest/features/deployed_server.html#deployed-server-with-config-download

```

### Satellite and OpenShift 4 KBase
https://access.redhat.com/solutions/5003361<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1798485<br>

### Kubernetes 1.22 对应的 csi 版本是 1.5.0 
https://github.com/kubernetes/kubernetes/blob/v1.22.0/go.mod#L28<br>
https://bugzilla.redhat.com/show_bug.cgi?id=2023197

### OSP Baremetal FIP security group
https://bugzilla.redhat.com/show_bug.cgi?id=2021261

### 使用 go modules 管理 kubernetes 依赖
https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/vendor.md

### 报错
```
[stack@overcloud-controller-0 ~]$ sudo cat /var/log/setup-ipa-client-ansible.log 
+ get_metadata_config_drive
+ '[' -f /run/cloud-init/status.json ']'
+ echo 'Unable to retrieve metadata from config drive.'
Unable to retrieve metadata from config drive.
+ return 1
+ get_metadata_network
++ timeout 300 /bin/bash -c 'data=""; while [ -z "$data" ]; do sleep $[ ( $RANDOM % 10 )  + 1 ]s; data=`curl -s http://169.254.169.254/openstack/2016-10-06/vendor_data2.json 2>/dev/null`; done; echo $data'
+ data=
+ [[ 124 != 0 ]]
+ echo 'Unable to retrieve metadata from metadata service.'
Unable to retrieve metadata from metadata service.
+ return 1
+ echo 'FATAL: No metadata available or could not read the hostname from the metadata'
FATAL: No metadata available or could not read the hostname from the metadata
+ exit 1

"<13>Nov 16 02:40:38 puppet-user: Error: /Stage[main]/Tripleo::Profile::Base::Certmonger_user/Tripleo::Certmonger::Libvirt_vnc[libvirt-vnc-server-cert]/Certmonger_certificate[libvirt-vnc-server-cert]: Could not evaluate: The certificate 'libvirt-vnc-server-cert' wasn't found in the list.",

"<13>Nov 16 03:42:56 puppet-user: Error: /Stage[main]/Tripleo::Certmonger::Ovn_controller/Certmonger_certificate[ovn_controller]: Could not evaluate: Could not get certificate: Error setting up ccache for \"host\" service on client using default keytab: Preauthentication failed.",
https://lists.fedoraproject.org/archives/list/freeipa-users@lists.fedorahosted.org/thread/ZUW57MXKU75IEKTQSHDYFSXEHI3QQCVA/?sort=date

https://lists.fedorahosted.org/archives/list/freeipa-users@lists.fedorahosted.org/thread/WDJZI4VIC6NP5LX6E3TMQCKMSG7IB4RU/

https://lists.fedorahosted.org/archives/list/freeipa-users@lists.fedorahosted.org/thread/XT5GZFGHVEQH2LH56UYC56EIXX2N6PTH/

klist -ekt /etc/krb5.keytab

[root@overcloud-controller-0 ~]# klist -k /etc/krb5.keytab 
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   1 host/overcloud-controller-0.example.com@EXAMPLE.COM
   1 host/overcloud-controller-0.example.com@EXAMPLE.COM

http://sammoffatt.com.au/jauthtools/Kerberos/Troubleshooting

ipa host-del example.com overcloud-controller-2.storagemgmt
ipa dnsrecord-del example.com overcloud-controller-2.storagemgmt --del-all

https://access.redhat.com/solutions/642993
ipa-getkeytab -s helper.example.com -k /etc/krb5.keytab -p host/overcloud-controller-0.example.com

报错: TASK [ipaclient : Install - IPA client test] *********************************************************************************************************
fatal: [undercloud.example.com]: FAILED! => {"changed": false, "msg": "Failed to verify that helper.example.com is an IPA Server."}

https://github.com/freeipa/ansible-freeipa/issues/337

ansible-playbook -vvv \
--ssh-extra-args "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
/usr/share/ansible/tripleo-playbooks/undercloud-ipa-install.yaml

TASK [tripleo_ipa_setup : add Nova Host Manager role] ************************************************************************************************
fatal: [localhost]: FAILED! => {"changed": false, "msg": "login: Request failed: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:897)>"}

TASK [tripleo_ipa_setup : add nova service] **********************************************************************************************************
task path: /usr/share/ansible/roles/tripleo_ipa_setup/tasks/add_ipa_user.yml:26

fatal: [localhost]: FAILED! => {
    "changed": false,
    "invocation": {
        "module_args": {
            "force": true,
            "hosts": null,
            "ipa_host": "helper.example.com",
            "ipa_pass": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
            "ipa_port": 443,
            "ipa_prot": "https",
            "ipa_timeout": 10,
            "ipa_user": "admin",
            "krbcanonicalname": "nova/undercloud.example.com",
            "name": "nova/undercloud.example.com",
            "state": "present",
            "validate_certs": true
        }
    },

    "msg": "response service_add: The host 'undercloud.example.com' does not exist to add a service to."

2021-11-17 10:50:31,304 p=1526 u=mistral n=ansible | fatal: [undercloud]: FAILED! => {
    "changed": false,
    "invocation": {
        "module_args": {
            "description": null,
            "force": true,
            "fqdn": "overcloud-computehci-0.example.com",
            "ip_address": null,
            "ipa_host": "helper.example.com",
            "ipa_pass": null,
            "ipa_port": 443,
            "ipa_prot": "https",
            "ipa_timeout": 10,
            "ipa_user": "nova/undercloud.example.com",
            "mac_address": null,
            "ns_hardware_platform": null,
            "ns_host_location": null,
            "ns_os_version": null,
            "random_password": true,
            "state": "present",
            "update_dns": null,
            "user_certificate": null,
            "validate_certs": true
        }
    },
    "msg": "host_find: HTTP Error 401: Unauthorized"
}

https://bugzilla.redhat.com/show_bug.cgi?id=1921855

(undercloud) [stack@undercloud ~]$ sudo kinit -kt /etc/novajoin/krb5.keytab nova/undercloud.example.com
kinit: Preauthentication failed while getting initial credentials

ipa privilege-find | grep -E "Privilege name:" 

https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/15/html/integrate_with_identity_service/idm-novajoin

(undercloud) [stack@undercloud ~]$ sudo kinit -kt /etc/novajoin/krb5.keytab nova/undercloud.example.com@EXAMPLE.COM 
kinit: Preauthentication failed while getting initial credentials

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/linux_domain_identity_authentication_and_policy_guide/retrieve-existing-keytabs
echo redhat123 | kinit admin
ipa-getkeytab -s helper.example.com -p nova/undercloud.example.com -k /etc/novajoin/krb5.keytab
klist
kdestroy
klist
kinit -kt /etc/novajoin/krb5.keytab nova/undercloud.example.com
klist
chmod a+r /etc/novajoin/krb5.keytab

echo redhat123 | sudo kinit admin
sudo klist
sudo ipa-join
sudo rm -f /etc/krb5.keytab
sudo ipa-getkeytab -s helper.example.com -p host/overcloud-controller-1.example.com -k /etc/krb5.keytab
sudo ls -l /etc/krb5.keytab
sudo chmod a+r /etc/krb5.keytab
klist
kdestroy -A
klist
kinit -kt /etc/krb5.keytab host/overcloud-controller-1.example.com
klist

ansible -i /tmp/inventory all -f 6 -m shell -a 'echo redhat123 | sudo kinit admin' 
ansible -i /tmp/inventory all -f 6 -m shell -a 'sudo ipa-join'
ansible -i /tmp/inventory all -f 6 -m shell -a 'sudo rm -f /etc/krb5.keytab'
ansible -i /tmp/inventory all -f 6 -m setup
# ansible 
ansible -vvv -i /tmp/inventory all -f 6 -m shell -a 'sudo echo $(hostname)'
ssh stack@192.0.2.51 "bash -c 'echo \$HOSTNAME'"
ssh stack@192.0.2.51 "bash -c 'echo \$(hostname)'"

# ssh overcloud node
sudo ipa-getkeytab -s helper.example.com -p host/$(hostname) -k /etc/krb5.keytab
# done

# ansible version
ansible -vvv -i /tmp/inventory all -f 6 -m shell -a 'sudo ipa-getkeytab -s helper.example.com -p host/$(hostname) -k /etc/krb5.keytab'


ansible -i /tmp/inventory all -f 6 -m shell -a "sudo chmod a+r /etc/krb5.keytab"
# ansible -i /tmp/inventory all -f 6 -m shell -a "kdestroy -A"
# ansible -i /tmp/inventory all -f 6 -m shell -a "kinit -kt /etc/krb5.keytab host/$hostname"
# ssh overcloud node
kdestroy -A; kinit -kt /etc/krb5.keytab host/$(hostname); klist
sudo kdestroy -A; sudo kinit -kt /etc/krb5.keytab host/$(hostname); sudo klist
# done

报错　
[jwang@undercloud ~]$ curl https://overcloud.ctlplane.example.com:8444 
curl: (51) SSL: no alternative certificate subject name matches target host name 'overcloud.ctlplane.example.com'

kinit: Keytab contains no suitable keys for host/undercloud.example.com@EXAMPLE.COM while getting initial credentials

ipa: ERROR: You must enroll a host in order to create a host service

(overcloud) [stack@undercloud ~]$ sudo cat /var/lib/mistral/overcloud/ansible.log | grep -E "fatal:" -A150 | grep Notice | head -1 | sed -e 's|\\n|\n|g'  | more
Notice: /Stage[main]/Tripleo::Profile::Pacemaker::Rabbitmq_bundle/File[/var/lib/rabbitmq/.erlang.cookie]/content: content changed '{md5}d952ac39fa2347
f946d23b9e1950f550' to '{md5}76cdd56d57e8c5b4a0845c400aac7c55'
Notice: /Stage[main]/Tripleo::Profile::Pacemaker::Rabbitmq_bundle/Exec[rabbitmq-ready]/returns: Error: unable to perform an operation on node 'rabbit@
overcloud-controller-0'. Please see diagnostics information and suggestions below.

rabbitmq_init_bundle Exited (1)


Nov 23 00:50:19 overcloud-controller-1.example.com systemd[1]: tripleo_ceilometer_agent_central_healthcheck.service: Main process exited, code=exited, status=1/FAILURE
Nov 23 00:50:19 overcloud-controller-1.example.com systemd[1]: tripleo_ceilometer_agent_central_healthcheck.service: Failed with result 'exit-code'.
Nov 23 00:50:19 overcloud-controller-1.example.com systemd[1]: Failed to start ceilometer_agent_central healthcheck.

[stack@overcloud-controller-1 ~]$ sudo systemctl status tripleo_ceilometer_agent_central_healthcheck.service 
 tripleo_ceilometer_agent_central_healthcheck.service - ceilometer_agent_central healthcheck
   Loaded: loaded (/etc/systemd/system/tripleo_ceilometer_agent_central_healthcheck.service; disabled; vendor preset: disabled)
   Active: failed (Result: exit-code) since Tue 2021-11-23 00:51:39 UTC; 3s ago
  Process: 105930 ExecStart=/usr/bin/podman exec --user root ceilometer_agent_central /openstack/healthcheck (code=exited, status=1/FAILURE)
 Main PID: 105930 (code=exited, status=1/FAILURE)

Nov 23 00:51:37 overcloud-controller-1.example.com systemd[1]: Starting ceilometer_agent_central healthcheck...
Nov 23 00:51:38 overcloud-controller-1.example.com podman[105930]: 2021-11-23 00:51:38.676923115 +0000 UTC m=+0.663368534 container exec bcdc4e363291>
Nov 23 00:51:38 overcloud-controller-1.example.com healthcheck_ceilometer_agent_central[105930]: sudo: unknown user: ceilome+
Nov 23 00:51:38 overcloud-controller-1.example.com healthcheck_ceilometer_agent_central[105930]: sudo: unable to initialize policy plugin
Nov 23 00:51:38 overcloud-controller-1.example.com healthcheck_ceilometer_agent_central[105930]: There is no ceilometer-polling process with opened R>
Nov 23 00:51:39 overcloud-controller-1.example.com healthcheck_ceilometer_agent_central[105930]: Error: non zero exit code: 1: OCI runtime error
Nov 23 00:51:39 overcloud-controller-1.example.com systemd[1]: tripleo_ceilometer_agent_central_healthcheck.service: Main process exited, code=exited>
Nov 23 00:51:39 overcloud-controller-1.example.com systemd[1]: tripleo_ceilometer_agent_central_healthcheck.service: Failed with result 'exit-code'.
Nov 23 00:51:39 overcloud-controller-1.example.com systemd[1]: Failed to start ceilometer_agent_central healthcheck.

https://bugzilla.redhat.com/show_bug.cgi?id=1902681


Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: grafana-server.service: Control process exited, code=exited status=125
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: grafana-server.service: Failed with result 'exit-code'.
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: Failed to start grafana-server.
Nov 23 01:08:11 overcloud-controller-2.example.com podman[180363]: Error: cannot remove container a81a811c5b4e9898d86ad1c23929feaa0cf18617e6649e069494b94cd174d951 as it is running - running or paused containers cannot be removed without force: container state improper
Nov 23 01:08:11 overcloud-controller-2.example.com podman[180357]: Error: error creating container storage: the container name "ceph-mgr-overcloud-controller-2" is already in use by "3e012222cd8213d3e6ed49ee55d145ca737cb8f4663896e5b8b7b962de3fc605". You have to remove that container to be able to reuse that name.: that name is already in use
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: ceph-mgr@overcloud-controller-2.service: Control process exited, code=exited status=125
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: ceph-mgr@overcloud-controller-2.service: Failed with result 'exit-code'.
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: Failed to start Ceph Manager.
Nov 23 01:08:11 overcloud-controller-2.example.com podman[180442]: Error: error creating container storage: the container name "ceph-mon-overcloud-controller-2" is already in use by "a81a811c5b4e9898d86ad1c23929feaa0cf18617e6649e069494b94cd174d951". You have to remove that container to be able to reuse that name.: that name is already in use
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: ceph-mon@overcloud-controller-2.service: Control process exited, code=exited status=125
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: ceph-mon@overcloud-controller-2.service: Failed with result 'exit-code'.
Nov 23 01:08:11 overcloud-controller-2.example.com systemd[1]: Failed to start Ceph Monitor.

sudo podman stop grafana-server
sudo podman stop ceph-mgr-overcloud-controller-2
sudo podman stop ceph-mon-overcloud-controller-2
```

### Mac terminal 报错 operation not permitted 的处理
https://osxdaily.com/2018/10/09/fix-operation-not-permitted-terminal-error-macos/

### Mac Big Sur 设置 remote viewer
https://rizvir.com/articles/ovirt-mac-console/

### Red Hat Satellite 6 创建 internal registry 
https://access.redhat.com/solutions/3233491

### Nutanix Labs

```
ncli datastore help 
ncli storagepool help
ncli container help

ncli user help
ncli user list

ncli container create help
ncli container create name=cli-container-jun sp-name=SP01

allssh manage_ovs show_interfaces
allssh manage_ovs show_bridges
allssh manage_ovs show_uplinks

# 支持的 Guest OS
https://portal.nutanix.com/page/documents/compatibility-matrix/guestos
```

### data path operation
https://www.ovirt.org/develop/release-management/features/storage/data-path-operations.html<bf>
https://access.redhat.com/documentation/zh-cn/red_hat_virtualization/4.0/html/administration_guide/the_storage_pool_managerspm<br>
https://www.ovirt.org/develop/developer-guide/vdsm/sanlock.html<br>

### Default repositories are missing in the RHEL 9 beta UBI
https://access.redhat.com/solutions/6527961<br>
https://developers.redhat.com/articles/faqs-no-cost-red-hat-enterprise-linux<br>

### TripleO Routed Networks Deployment (Spine-and-Leaf Clos)
https://specs.openstack.org/openstack/tripleo-specs/specs/queens/tripleo-routed-networks-deployment.html<br>
[RFE][Tracker] Enable BGP Routing For Spine-Leaf Deployments<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1896551<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1791821<br>
https://specs.openstack.org/openstack/neutron-specs/specs/liberty/ipv6-prefix-delegation.html<br>
https://specs.openstack.org/openstack/neutron-specs/specs/ussuri/ml2ovs-ovn-convergence.html#feature-gap-analysis<br>
https://github.com/alauda/kube-ovn/blob/f2dc37ceca28ed984511b351ce22a040bf749975/docs/bgp.md<br>
https://object-storage-ca-ymq-1.vexxhost.net/swift/v1/6e4619c416ff4bd19e1c087f27a43eea/www-assets-prod/presentation-media/20170508-IPv6-Lessons.pdf<br>
https://etherpad.opendev.org/p/neutron-xena-ptg<br>
https://etherpad.opendev.org/p/tripleo-frr-integration<br>
https://www.youtube.com/watch?v=9DL8M1d4xLY<br>

### OCP 4.9 use aws object storage as registry storage
https://docs.openshift.com/container-platform/4.9/registry/configuring_registry_storage/configuring-registry-storage-aws-user-infrastructure.html

### 王征的 OCP 仓库
https://github.com/wangzheng422/docker_env

### OVS-DPDK - The group RxQ-to-PMD assignment type
https://developers.redhat.com/articles/2021/11/19/improve-multicore-scaling-open-vswitch-dpdk#other_rxq_considerations

### Red Hat Virtualization no longer supports software FCoE starting with version 4.4
https://access.redhat.com/solutions/5269201

### 检查控制节点的 neutron plugin ml2 extension_dirvers
```
[stack@overcloud-controller-2 ~]$ sudo grep -A10 neutron::plugins::ml2::extension_drivers  /etc/puppet/hieradata/service_configs.json
    "neutron::plugins::ml2::extension_drivers": [
        "qos",
        "port_security",
        "dns"
    ],
    "neutron::plugins::ml2::firewall_driver": "iptables_hybrid",
    "neutron::plugins::ml2::flat_networks": [
        "datacentre"
    ],
...
```
### 检查最新的 config-download 是否包含某个配置
```
(overcloud) [stack@undercloud ~]$ sudo grep -r port_security /var/lib/mistral/config-download-latest/ | grep -Ev ansible.log
/var/lib/mistral/config-download-latest/Controller/config_settings.yaml:- port_security
/var/lib/mistral/config-download-latest/group_vars/Controller:  - port_security
```

### Role Specific Parameters
https://docs.openstack.org/project-deploy-guide/tripleo-docs/latest/features/role_specific_parameters.html

NeutronPluginExtensions 不是一个 Role Specific Parameter

### OCS/ODF crash 处理
```
ceph health detail
ceph status
ceph crash ls
ceph crash archive-all

# 不见得需要执行
# ceph crash rm <id>
```

### Implementing Security Groups in OpenStack using OVN Port Groups
http://dani.foroselectronica.es/implementing-security-groups-in-openstack-using-ovn-port-groups-478/

### Deploying Overcloud with L3 routed networking
https://docs.openstack.org/project-deploy-guide/tripleo-docs/latest/features/routed_spine_leaf_network.html

### 深入理解 TripleO
https://www.bookstack.cn/read/deep-understanding-of-tripleo/%E5%B0%81%E9%9D%A2.md

# undercloud.conf 文件参数解释
https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/16.0/html/director_installation_and_usage/installing-the-undercloud
```
# 根据以下解释，如果希望 ctlplane subnet 通过 masquerade 的方式通过 undercloud 访问外网，就把这个参数设置为 true 
masquerade
Defines whether to masquerade the network defined in the cidr for external access. This provides the Provisioning network with a degree of network address translation (NAT) so that the Provisioning network has external access through director.

# 生成 rhel 8.2 的配置文件
kernel parameters  
ks=http://10.66.208.115/ks-undercloud.cfg ksdevice=ens3 ip=10.66.208.121 netmask=255.255.255.0 dns 10.64.63.6 gateway=10.66.208.254

cat > ks-undercloud.cfg << 'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
poweroff
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart --nohome
network --device=ens3 --hostname=undercloud.example.com --bootproto=static --ip=10.66.208.121 --netmask=255.255.255.0 --gateway=10.66.208.254 --nameserver=10.64.63.6
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
createrepo
vim
yum-utils
wget
%end
EOF

> /etc/yum.repos.d/osp.repo
for i in rhel-8-for-x86_64-baseos-eus-rpms rhel-8-for-x86_64-appstream-eus-rpms rhel-8-for-x86_64-highavailability-eus-rpms ansible-2.9-for-rhel-8-x86_64-rpms openstack-16.1-for-rhel-8-x86_64-rpms fast-datapath-for-rhel-8-x86_64-rpms rhceph-4-tools-for-rhel-8-x86_64-rpms advanced-virt-for-rhel-8-x86_64-rpms
do
cat >> /etc/yum.repos.d/osp.repo << EOF
[$i]
name=$i
baseurl=file:///var/www/html/repos/osp16.1/$i/
enabled=1
gpgcheck=0

EOF
done

tar zcvf /tmp/osp16.1-yum-repos-$(date -I).tar.gz /var/www/html/repos/OSP16_1_repo_sync_up.sh /var/www/html/repos/osp16.1

tar zcvf /home/osp16.1-poc-registry-$(date -I).tar.gz /opt/registry


```

### 重启运行self hosted engine的服务器
参考： https://access.redhat.com/solutions/2486301
```
hosted-engine --vm-shutdown 
hosted-engine --vm-status
virsh -r list
reboot

# 重启后，执行
systemctl stop ovirt-ha-agent
systemctl stop ovirt-ha-broker
systemctl restart nfs-server
systemctl start ovirt-ha-broker
systemctl start ovirt-ha-agent

# 检查服务状态
systemctl status ovirt-ha-broker
systemctl status ovirt-ha-agent

# 检查 hosted-engine 状态
hosted-engine --vm-status
hosted-engine --vm-start
watch hosted-engine --vm-status
hosted-engine --set-maintenance --mode=none
```

### undercloud.conf 的内容
```
# cat /usr/share/python-tripleoclient/undercloud.conf.sample
# 普通部署
# 部署时定义了 subnets 和 local_subnet 
# subnets 只定义了 1 个 subnet ctlplane-subnet
# local_subnet 是 ctlplane-subnet
# ctlplane-subnet 的定义包括
# cidr 网段
# dhcp_start 和 dhcp_stop
# inspection_iprange 定义了 inttrospection 时使用的 ip 范围
# gateway
# masquerade
cat > undercloud.conf <<EOF
[DEFAULT]
undercloud_hostname = undercloud.example.com
container_images_file = containers-prepare-parameter.yaml
local_ip = 192.0.2.1/24
undercloud_public_host = 192.0.2.2
undercloud_admin_host = 192.0.2.3
subnets = ctlplane-subnet
local_subnet = ctlplane-subnet
local_interface = ens10
inspection_extras = true
undercloud_debug = false
enable_tempest = false
enable_ui = false
clean_nodes = true
overcloud_domain_name = example.com
undercloud_nameservers = 192.168.122.3

[auth]
undercloud_admin_password = redhat

[ctlplane-subnet]
cidr = 192.0.2.0/24
dhcp_start = 192.0.2.5
dhcp_end = 192.0.2.24
inspection_iprange = 192.0.2.100,192.0.2.120
gateway = 192.0.2.1
masquerade = true
EOF


```

### osp 的 rpm 版本信息可以参见 openstack-16.1-for-rhel-8-x86_64-rpms 仓库的 rhosp-release 软件包

### BaiduPCS-Go 下载
https://github.com/qjfoidnh/BaiduPCS-Go/releases/tag/v3.8.4<br>
https://github.com/GangZhuo/BaiduPCS.git<br>
https://blog.csdn.net/ykiwmy/article/details/103730962<br>
```
# 登陆
BaiduPCS-Go login -bduss=<BDUSS>
# 上传文件
BaiduPCS-Go upload osp16.1-yum-repos-2021-11-25.tar.gz /osp16.1/repos
```


### rhel8  
```
# update dnf 相关软件
# yum list all | grep dnf | grep -E "anaconda|AppStream"  | awk '{print $1}' | while read i ; do yum update -y $i ; done 

# yum clean all
# yum repolist 
# yum install -y chrony

# 查看接口 TX RX 数据包信息
ip -s link show dev ens3
```

### Red Hat Solutions - Result: hostbyte=DID_ERROR driverbyte=DRIVER_OK
https://access.redhat.com/solutions/438403

### 命令历史控制
```
关闭命令历史 
set +o history

打开命令历史
set -o history
```
 
### 记录
```
https://www.jianshu.com/p/55c22e455ec9
https://zhuanlan.zhihu.com/p/84026420
术语
PLC - Programmable Logic Controller- 可编程逻辑控制器 - 现场设备层
SCADA - Supervisory Control And Data AcquiSition System - 数据采集与监控系统 - 调度管理层
HMI - Human Machine Interface - 人机界面 - 是系统和用户之间进行交互和信息交换的媒介
PPS - Production Pull System - 生产拉动系统 - 基于预测未来消耗，有计划补充物料
MES - Manufacturing Execution System - 制造执行系统 - 面向制造企业车间执行层的生产信息化管理系统
PLM - Product Lifecycle Management - 产品生命周期管理 - 
ERP - Enterprise Resource Planning - 企业资源计划管理 全程企业资源规划 公司综合管理系统 - 管理层

https://zhuanlan.zhihu.com/p/43002417
什么是GitOps？
GitOps是一种持续交付的方式。它的核心思想是将应用系统的声明性基础架构和应用程序存放在Git版本库中。

DaemonSet 确保所有（或部分）节点运行一个 Pod 的副本。 如果 Node 与集群断开连接，那么 k8s API 中的 Daemonset Pod 将不会改变状态，并将继续保持上次报告的状态。

在网络中断期间如果节点重新启动，将不重新启动工作负载

当节点网络中断恢复节点重新加入集群时，工作负载重新启动

如果工作负载在所有 Remote Worker Nodes 上运行时建议使用 DaemonSet 运行工作负载。 DaemonSet 还支持 Service Endpoint 和 Load Balancer。

Static Pod 由特定节点上的 kubelet 守护进程管理。 与由 k8s 控制平面管理的 Pod 不同，节点的 kubelet 负责监视每个Static Pod。

在 Pod-eviction-timeout 之后调度 Pod 的其他方法；

减缓 pod evict...
通常，对于无法访问的受污染节点，控制器以每 10 秒 1 个节点的速率执行 pod evict，使用区域控制器后以每 100 秒驱逐 1 个节点的速率执行 pod evict。
少于 50 个节点的集群不会标记Tainted，并且您的集群必须具有 3 个以上的区域才能生效。

https://docs.openstack.org/neutron/wallaby/admin/ovn/router_availability_zones.html

ml2/ovn 的实现
https://docs.openstack.org/neutron/wallaby/admin/ovn/router_availability_zones.html

$ ovs-vsctl set Open_vSwitch . \
external-ids:ovn-cms-options="enable-chassis-as-gw,availability-zones=az-0:az-1:az-2"
上面的命令在 external-ids:ovn-cms-options 选项中添加了两个配置，enable-chassis-as-gw 选项告诉 OVN 驱动程序这是一个网关/网络节点，available-zones 选项指定三个可用区：az -0、az-1 和 az-2。


在 Pod-eviction-timeout 之后重新安排 Pod 的其他方法；

缺点
在没有来自 API 服务器的任何触发的情况下，是否通过节点重新启动来重新启动工作负载


减缓 pod 驱逐...
通常，对于无法访问的受污染节点，控制器以每 10 秒 1 个节点的速率驱逐 pod，使用区域控制器以每 100 秒驱逐 1 个节点的速率驱逐。少于 50 个节点的集群不会被污染，并且您的集群必须有 3 个以上的区域才能生效。

当连接恢复时，在 Pod-eviction-timeout 或 tolerationSeconds 到期之前，节点会在控制平面管理下返回
如果容忍秒数 = 0，容忍可以无限期地减轻 pod 驱逐；
或者使用给定污点的指定值延长 pod 驱逐超时；
$ openstack network agent list
+--------------------------------------+------------------------------+----------------+-------------------+-------+-------+----------------+
| ID                                   | Agent Type                   | Host           | Availability Zone | Alive | State | Binary         |
+--------------------------------------+------------------------------+----------------+-------------------+-------+-------+----------------+
| 2d1924b2-99a4-4c6c-a4f2-0be64c0cec8c | OVN Controller Gateway agent | gateway-host-0 | az0, az1, az2     | :-)   | UP    | ovn-controller |
+--------------------------------------+------------------------------+----------------+-------------------+-------+-------+----------------+

$ openstack router create --availability-zone-hint az-0 --availability-zone-hint az-1 router-0
+-------------------------+--------------------------------------+
| Field                   | Value                                |
+-------------------------+--------------------------------------+
| admin_state_up          | UP                                   |
| availability_zone_hints | az-0, az-1                           |
| availability_zones      |                                      |
| created_at              | 2020-06-04T08:29:33Z                 |
| description             |                                      |
| external_gateway_info   | null                                 |
| flavor_id               | None                                 |
| id                      | 8fd6d01a-57ad-4e91-a788-ebe48742d000 |
| name                    | router-0                             |
| project_id              | 2a364ced6c084888be0919450629de1c     |
| revision_number         | 1                                    |
| routes                  |                                      |
| status                  | ACTIVE                               |
| tags                    |                                      |
| updated_at              | 2020-06-04T08:29:33Z                 |
+-------------------------+--------------------------------------+

Playbook - 用来创建 osp 16.2 dcn 的环境
https://gitlab.cee.redhat.com/sputhenp/lab/-/blob/master/recreate-infra.yaml -e "osp_version=16" osp_sub_version=2 dcn=1"
```

### windows add route 命令
https://www.jianshu.com/p/c99c267f3f8d<br>
https://stackoverflow.com/questions/4974131/how-to-create-ssh-tunnel-using-putty-in-windows<br>
```
# 希望达到的效果是，在 Windows Putty 这边访问 127.0.0.1:13808 通过 ssh 隧道转发到 192.168.122.40:13808 上
# Connection -> SSH -> Tunnels
# Source port: 13808
# Destination: 192.168.122.40:13808
# 选中：Local
# 选中：Auto
# Add
# L13808 192.168.122.40:13808
# L80 192.168.122.40:80
# L443 192.168.122.40:443
# L8444 192.168.122.40:8444
# L3100 192.168.122.40:3100
# Open
```

```
# 在 window 这边添加主机路由
route -p add 192.168.122.1 mask 255.255.255.255 10.66.208.240

# 建立 putty ssh 隧道
# https://tecadmin.net/putty-ssh-tunnel-and-port-forwarding/

# 编辑 windows hosts 文件
# c:\Windows\System32\Drivers\etc\hosts

# Windows 10 添加证书
# https://docs.fortinet.com/document/fortiauthenticator/5.5.0/cookbook/494798/manually-importing-the-client-certificate-windows-10

# rclone 如何设置不检查证书？
# https://github.com/rclone/rclone/issues/168
# rclone.exe --no-check-certificate lsd s3:
# 注意将本地时间与 s3 服务器时间配置成一致的时间
```

### Infraed 相关资料
https://github.com/sean-m-sullivan/infrared_custom_documentation

### CephFS 
https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html-single/file_system_guide/index#exporting-ceph-file-system-namespaces-over-the-nfs-protocol_fs<br>
https://documentation.suse.com/zh-cn/ses/6/html/ses-all/cha-ses-cifs.html<br>

S3 Client<br>
https://rclone.org/<br>
https://mountainduck.io/<br>

s3browse 用 s3 协议访问 ceph bucket<br>
https://blog.csdn.net/wuguifa/article/details/109605973<br>
Endpoint: overcloud.example.com:13808<br>
Use secure transfer (SSL/TLS): true<br>

rook ceph dashboard<br>
https://github.com/rook/rook/blob/master/Documentation/ceph-dashboard.md<br>

kubernetes csi drivers<br>
https://kubernetes-csi.github.io/docs/drivers.html<br>

### ImageBuild Service
https://console.redhat.com/beta/insights/image-builder<br>

### migration from self host engine to another self host engine
https://access.redhat.com/documentation/en-us/red_hat_virtualization/4.4/html/self-hosted_engine_guide/restoring_the_backup_on_a_new_self-hosted_engine_migrating_to_she<br>

### 获取 ceph rgw 的 haproxy 配置
```
# 查看 rgw 的 haproxy 配置
# 192.168.122.40 对应 public/external endpoint
[stack@overcloud-controller-0 ~]$ sudo -i cat /var/lib/config-data/puppet-generated/haproxy/etc/haproxy/haproxy.cfg | grep rgw -A12
listen ceph_rgw
  bind 172.16.1.240:8080 transparent ssl crt /etc/pki/tls/certs/haproxy/overcloud-haproxy-storage.pem
  bind 192.168.122.40:13808 transparent ssl crt /etc/pki/tls/private/overcloud_endpoint.pem
  mode http
  http-request set-header X-Forwarded-Proto https if { ssl_fc }
  http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
  http-request set-header X-Forwarded-Port %[dst_port]
  option httpchk GET /swift/healthcheck
  redirect scheme https code 301 if { hdr(host) -i 192.168.122.40 } !{ ssl_fc }
  rsprep ^Location:\ http://(.*) Location:\ https://\1
  server overcloud-controller-0.storage.example.com 172.16.1.51:8080 ca-file /etc/ipa/ca.crt check fall 5 inter 2000 rise 2 ssl verify required verifyhost overcloud-controller-0.storage.example.com
  server overcloud-controller-1.storage.example.com 172.16.1.52:8080 ca-file /etc/ipa/ca.crt check fall 5 inter 2000 rise 2 ssl verify required verifyhost overcloud-controller-1.storage.example.com
  server overcloud-controller-2.storage.example.com 172.16.1.53:8080 ca-file /etc/ipa/ca.crt check fall 5 inter 2000 rise 2 ssl verify required verifyhost overcloud-controller-2.storage.example.com

# 从 undercloud 访问 192.168.122.40:13808 对应的 url (overcloud.example.dom)
[stack@overcloud-controller-0 ~]$ curl https://overcloud.example.com:13808
<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>anonymous</ID><DisplayName></DisplayName></Owner><Buckets></Buckets></ListAllMyBucketsResult>
[stack@overcloud-controller-0 ~]$ 

# 创建用户
# uid: admin
# display-name: admin
# access-key: admin
# secret-key: admin123
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-rgw-overcloud-controller-0-rgw0 radosgw-admin user create --uid='admin' --display-name='admin' --access-key='admin' --secret-key='admin123'

# 安装 aws cli
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
(overcloud) [stack@undercloud ~]$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
(overcloud) [stack@undercloud ~]$ unzip awscliv2.zip
(overcloud) [stack@undercloud ~]$ sudo ./aws/install

# 配置一下 aws s3 client
# 设置 access key
# 设置 secret key
# 注意，需要设置 Default region name，否则 mkbucket 时将会有报错
# make_bucket failed: s3://mybucket An error occurred (InvalidLocationConstraint) when calling the CreateBucket operation: The specified location-constraint is not valid

(overcloud) [stack@undercloud ~]$ aws configure 
AWS Access Key ID [None]: admin
AWS Secret Access Key [None]: admin123
Default region name [None]: us-east-1
Default output format [None]: 

# 查看 bucket
# 设置环境变量 AWS_CA_BUNDLE
# https://www.shellhacks.com/aws-cli-ssl-validation-failed-solved/
(overcloud) [stack@undercloud ~]$ export AWS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
(overcloud) [stack@undercloud ~]$ aws --endpoint=https://overcloud.example.com:13808 s3 ls
# 创建 bucket
(overcloud) [stack@undercloud ~]$ aws --endpoint=https://overcloud.example.com:13808 s3 mb s3://mybucket
make_bucket: mybucket
# 上传文件到 bucket
(overcloud) [stack@undercloud ~]$ aws --endpoint=https://overcloud.example.com:13808 s3 cp /home/stack/overcloudrc s3://mybucket
upload: ./overcloudrc to s3://mybucket/overcloudrc  

# 设置 alias 
# https://github.com/aws/aws-cli/issues/4454
(overcloud) [stack@undercloud ~]$ alias aws='aws --endpoint-url https://overcloud.example.com:13808'
(overcloud) [stack@undercloud ~]$ aws s3 ls 
2021-11-30 09:57:51 mybucket

# 下载 rclone 
# https://downloads.rclone.org/v1.57.0/rclone-v1.57.0-linux-amd64.zip
(overcloud) [stack@undercloud ~]$ unzip /tmp/rclone-v1.57.0-linux-amd64.zip
(overcloud) [stack@undercloud ~]$ sudo cp rclone-v1.57.0-linux-amd64/rclone /usr/local/bin/ 
(overcloud) [stack@undercloud ~]$ rclone config
2021/11/30 10:13:08 NOTICE: Config file "/home/stack/.config/rclone/rclone.conf" not found - using defaults
No remotes found - make a new one
n) New remote
s) Set configuration password
q) Quit config
n/s/q> n
name> s3
Option Storage.
Type of storage to configure.
Enter a string value. Press Enter for the default ("").
Choose a number from below, or type in your own value.
 1 / 1Fichier
   \ "fichier"
 2 / Alias for an existing remote
   \ "alias"
 3 / Amazon Drive
   \ "amazon cloud drive"
 4 / Amazon S3 Compliant Storage Providers including AWS, Alibaba, Ceph, Digital Ocean, Dreamhost, IBM COS, Minio, SeaweedFS, and Tencent COS
   \ "s3"
...
Storage> 4
Option provider.
Choose your S3 provider.
Enter a string value. Press Enter for the default ("").
Choose a number from below, or type in your own value.
 1 / Amazon Web Services (AWS) S3
   \ "AWS"
 2 / Alibaba Cloud Object Storage System (OSS) formerly Aliyun
   \ "Alibaba"
 3 / Ceph Object Storage
   \ "Ceph"
 4 / Digital Ocean Spaces
   \ "DigitalOcean"
provider> 3

Option env_auth.
Get AWS credentials from runtime (environment variables or EC2/ECS meta data if no env vars).
Only applies if access_key_id and secret_access_key is blank.
Enter a boolean value (true or false). Press Enter for the default ("false").
Choose a number from below, or type in your own value.
 1 / Enter AWS credentials in the next step.
   \ "false"
 2 / Get AWS credentials from the environment (env vars or IAM).
   \ "true"
env_auth> 1

Option access_key_id.
AWS Access Key ID.
Leave blank for anonymous access or runtime credentials.
Enter a string value. Press Enter for the default ("").
access_key_id> admin

Option secret_access_key.
AWS Secret Access Key (password).
Leave blank for anonymous access or runtime credentials.
Enter a string value. Press Enter for the default ("").
secret_access_key> admin123

Option region.
Region to connect to.
Leave blank if you are using an S3 clone and you don't have a region.
Enter a string value. Press Enter for the default ("").
Choose a number from below, or type in your own value.
   / Use this if unsure.
 1 | Will use v4 signatures and an empty region.
   \ ""
   / Use this only if v4 signatures don't work.
 2 | E.g. pre Jewel/v10 CEPH.
   \ "other-v2-signature"
region> 1

Option endpoint.
Endpoint for S3 API.
Required when using an S3 clone.
Enter a string value. Press Enter for the default ("").
endpoint> https://overcloud.example.com:13808

Option location_constraint.
Location constraint - must be set to match the Region.
Leave blank if not sure. Used when creating buckets only.
Enter a string value. Press Enter for the default ("").
location_constraint> 

Option acl.
Canned ACL used when creating buckets and storing or copying objects.
This ACL is used for creating objects and if bucket_acl isn't set, for creating buckets too.
For more info visit https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl
Note that this ACL is applied when server-side copying objects as S3
doesn't copy the ACL from the source but rather writes a fresh one.
Enter a string value. Press Enter for the default ("").
acl> 

Option server_side_encryption.
The server-side encryption algorithm used when storing this object in S3.
Enter a string value. Press Enter for the default ("").
server_side_encryption>

Option sse_kms_key_id.
If using KMS ID you must provide the ARN of Key.
Enter a string value. Press Enter for the default ("").
sse_kms_key_id> 

Edit advanced config?
y) Yes
n) No (default)
y/n> 
--------------------
[s3]
type = s3
provider = Ceph
access_key_id = admin
secret_access_key = admin123
endpoint = https://overcloud.example.com:13808
--------------------
y) Yes this is OK (default)
e) Edit this remote
d) Delete this remote
y/e/d> 
Current remotes:

Name                 Type
====                 ====
s3                   s3

e) Edit existing remote
n) New remote
d) Delete remote
r) Rename remote
c) Copy remote
s) Set configuration password
q) Quit config
e/n/d/r/c/s/q> q

# https://rclone.org/s3/

# 查看 all buckets
rclone lsd s3:

# 使用 rclone 时需要 unset AWS_CA_BUNDLE
# https://forum.rclone.org/t/mounting-an-amazon-s3-bucket/15106
# 否则有报错
# "Failed to create file system for mountname:bucketname: LoadCustomCABundleError: unable to load custom CA bundle, HTTPClient's transport unsupported type"
(overcloud) [stack@undercloud ~]$ unset AWS_CA_BUNDLE 
(overcloud) [stack@undercloud ~]$ rclone lsd s3:
          -1 2021-11-30 09:57:51        -1 mybucket
# 查看 bucket
(overcloud) [stack@undercloud ~]$ rclone ls s3:mybucket
     1015 overcloudrc

(overcloud) [stack@undercloud ~]$ rclone copy /home/stack/stackrc s3:mybucket
(overcloud) [stack@undercloud ~]$ rclone ls s3:mybucket
     1015 overcloudrc
      774 stackrc

# 查看 pool 的情况
(overcloud) [stack@undercloud ~]$ ssh stack@192.0.2.51
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd dump | grep pool

[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph health detail
HEALTH_WARN 10 pools have too many placement groups
POOL_TOO_MANY_PGS 10 pools have too many placement groups
    Pool vms has 128 placement groups, should have 32
    Pool volumes has 128 placement groups, should have 32
    Pool images has 128 placement groups, should have 32
    Pool .rgw.root has 128 placement groups, should have 32
    Pool default.rgw.control has 128 placement groups, should have 32
    Pool default.rgw.meta has 128 placement groups, should have 32
    Pool default.rgw.log has 128 placement groups, should have 32
    Pool default.rgw.buckets.index has 128 placement groups, should have 32
    Pool default.rgw.buckets.data has 128 placement groups, should have 32
    Pool default.rgw.buckets.non-ec has 128 placement groups, should have 32

# 查看 pool 的 autoscale-status 
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool autoscale-status 
POOL                         SIZE TARGET SIZE RATE RAW CAPACITY  RATIO TARGET RATIO EFFECTIVE RATIO BIAS PG_NUM NEW PG_NUM AUTOSCALE 
vms                            0               3.0       899.9G 0.0000                               1.0    128         32 warn      
volumes                        0               3.0       899.9G 0.0000                               1.0    128         32 warn      
images                      9216M              3.0       899.9G 0.0300                               1.0    128         32 warn      
.rgw.root                   3653               3.0       899.9G 0.0000                               1.0    128         32 warn      
default.rgw.control            0               3.0       899.9G 0.0000                               1.0    128         32 warn      
default.rgw.meta            1088               3.0       899.9G 0.0000                               1.0    128         32 warn      
default.rgw.log             4519               3.0       899.9G 0.0000                               1.0    128         32 warn      
default.rgw.buckets.index  10832               3.0       899.9G 0.0000                               1.0    128         32 warn      
default.rgw.buckets.data   30556k              3.0       899.9G 0.0001                               1.0    128         32 warn      
default.rgw.buckets.non-ec     0               3.0       899.9G 0.0000                               1.0    128         32 warn   

# 默认的 autoscale 设置为 'warn'，触发告警
# https://docs.ceph.com/en/latest/rados/operations/placement-groups/
# 手工调整为 'on'
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph config set global osd_pool_default_pg_autoscale_mode on

# 查看参数调整情况
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph config dump
WHO    MASK LEVEL    OPTION                                           VALUE                                    RO 
global      advanced osd_pool_default_pg_autoscale_mode               on                                          
  mgr       advanced mgr/dashboard/ALERTMANAGER_API_HOST              http://172.16.1.51:9093                  *  
  mgr       advanced mgr/dashboard/GRAFANA_API_PASSWORD               KpjNWnN7rA9w9AA5SuDvcfK59                *  
  mgr       advanced mgr/dashboard/GRAFANA_API_SSL_VERIFY             false                                    *  
  mgr       advanced mgr/dashboard/GRAFANA_API_URL                    https://192.0.2.240:3100                 *  
  mgr       advanced mgr/dashboard/GRAFANA_API_USERNAME               admin                                    *  
  mgr       advanced mgr/dashboard/PROMETHEUS_API_HOST                http://172.16.1.51:9092                  *  
  mgr       advanced mgr/dashboard/RGW_API_ACCESS_KEY                 7LECDPNKIA22FFE78X1Y                     *  
  mgr       advanced mgr/dashboard/RGW_API_HOST                       172.16.1.51                              *  
  mgr       advanced mgr/dashboard/RGW_API_PORT                       8080                                     *  
  mgr       advanced mgr/dashboard/RGW_API_SCHEME                     https                                    *  
  mgr       advanced mgr/dashboard/RGW_API_SECRET_KEY                 lmJx68zSRUw9M13gAtZIDxzVD0KUxULroXdGInnq *  
  mgr       advanced mgr/dashboard/RGW_API_USER_ID                    ceph-dashboard                           *  
  mgr       advanced mgr/dashboard/overcloud-controller-0/server_addr 172.16.1.51                              *  
  mgr       advanced mgr/dashboard/overcloud-controller-1/server_addr 172.16.1.52                              *  
  mgr       advanced mgr/dashboard/overcloud-controller-2/server_addr 172.16.1.53                              *  
  mgr       advanced mgr/dashboard/server_port                        8444                                     *  
  mgr       advanced mgr/dashboard/ssl                                true                                     *  
  mgr       advanced mgr/dashboard/ssl_server_port                    8444                                     *  


[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph config get mon.0
WHO    MASK LEVEL    OPTION                             VALUE RO 
global      advanced osd_pool_default_pg_autoscale_mode on       
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph config get osd.0
WHO    MASK LEVEL    OPTION                             VALUE RO 
global      advanced osd_pool_default_pg_autoscale_mode on       
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph config get osd.1
WHO    MASK LEVEL    OPTION                             VALUE RO 
global      advanced osd_pool_default_pg_autoscale_mode on 

# 手工设置 pool 的 pg_autoscale_mode 为 on
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph health detail | grep Pool | awk '{print $2}' | while read i ;do echo sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set $i pg_autoscale_mode on ; done

sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set volumes pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set images pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set .rgw.root pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set default.rgw.control pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set default.rgw.meta pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set default.rgw.log pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set default.rgw.buckets.index pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set default.rgw.buckets.data pg_autoscale_mode on
sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool set default.rgw.buckets.non-ec pg_autoscale_mode on

# 这些命令执行下来之后，ceph status 转变为 ‘HEALTH_OK’ 了
# https://docs.ceph.com/en/latest/rados/operations/placement-groups/
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph health detail 
HEALTH_OK
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph osd pool autoscale-status
POOL                         SIZE TARGET SIZE RATE RAW CAPACITY  RATIO TARGET RATIO EFFECTIVE RATIO BIAS PG_NUM NEW PG_NUM AUTOSCALE 
vms                            0               3.0       899.9G 0.0000                               1.0     32            on        
volumes                        0               3.0       899.9G 0.0000                               1.0     32            on        
images                      9421M              3.0       899.9G 0.0307                               1.0     32            on        
.rgw.root                   3653               3.0       899.9G 0.0000                               1.0     32            on        
default.rgw.control            0               3.0       899.9G 0.0000                               1.0     32            on        
default.rgw.meta            1088               3.0       899.9G 0.0000                               1.0     32            on        
default.rgw.log             4548               3.0       899.9G 0.0000                               1.0     32            on        
default.rgw.buckets.index  10832               3.0       899.9G 0.0000                               1.0     32            on        
default.rgw.buckets.data   30919k              3.0       899.9G 0.0001                               1.0     32            on        
default.rgw.buckets.non-ec     0               3.0       899.9G 0.0000                               1.0     32            on  

# 查看 radosgw user 'ceph-dashboard' 相关信息 
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-rgw-overcloud-controller-0-rgw0 radosgw-admin user info --uid='ceph-dashboard'
{
    "user_id": "ceph-dashboard",  
    "display_name": "Ceph dashboard",
    "email": "",
    "suspended": 0,
    "max_buckets": 1000,
    "subusers": [],
    "keys": [
        {
            "user": "ceph-dashboard",
            "access_key": "7LECDPNKIA22FFE78X1Y",
            "secret_key": "lmJx68zSRUw9M13gAtZIDxzVD0KUxULroXdGInnq"
        }
    ],
    "swift_keys": [],
    "caps": [],
    "op_mask": "read, write, delete",
    "system": "true",
    "default_placement": "",
    "default_storage_class": "",
    "placement_tags": [],
    "bucket_quota": {
        "enabled": false,
        "check_on_raw": false,
        "max_size": -1,
        "max_size_kb": 0,
        "max_objects": -1
    },
    "user_quota": {
        "enabled": false,
        "check_on_raw": false,
        "max_size": -1,
        "max_size_kb": 0,
        "max_objects": -1
    },                             
    "temp_url_keys": [],
    "type": "rgw",
    "mfa_ids": []
}

# 在 ceph dashboard 上访问 Object Gateway 时报 404
# https://docs.ceph.com/en/latest/mgr/dashboard/#dashboard-enabling-object-gateway
# 设置 ceph dashboard set-rgw-api-ssl-verify False
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph dashboard set-rgw-api-ssl-verify False 
Option RGW_API_SSL_VERIFY updated
[stack@overcloud-controller-0 ~]$ sudo podman exec -it ceph-mon-overcloud-controller-0 ceph config dump 
WHO    MASK LEVEL    OPTION                                           VALUE                                    RO 
[TRUNCATED]
  mgr       advanced mgr/dashboard/RGW_API_SSL_VERIFY                 false                                    *  
[TRUNCATED]

这是一些 s3 图形化客户端软件
winscp - Windows
https://winscp.net/eng/docs/guide_amazon_s3
cloudberry - Windows
https://cloudberry-explorer-for-amazon-s3.en.softonic.com/
cyberduck - Mac, Windows
https://cyberduck.io/s3/
rclone - Linux, Windows
https://rclone.org/gui/
https://github.com/guimou/rclone-web-on-openshift
```

### 增加 tripleo firewall 规则的模版
```
# 注意：
# 1. 以下模版内容可以在默认 tripleo firewall rule 的基础上追加规则
# 2. 作用的位置在 'INPUT' Chain 和 'filter' table
parameter_defaults:
  PurgeFirewallRules: true 
  ExtraConfig:
    tripleo::firewall::firewall_rules:
      '005 allow SSH from X.X.X.X/24':
        dport: 22
        proto: tcp
        source: X.X.X.X/24
      '006 allow SSH from X.X.X.X/22':
        dport: 22
        proto: tcp
        source: X.X.X.X/22
      '007 allow SSH from X.X.X.X/22':
        dport: 22
        proto: tcp
        source: X.X.X.X/22
      '008 allow SSH from X.X.X.X/21':
        dport: 22
        proto: tcp
        source: X.X.X.X/21
      '009 allow SSH from X.X.X.X/26':
        dport: 22
        proto: tcp
        source: X.X.X.X/26
      '010 allow SSH from X.X.X.X/32':
        dport: 22
        proto: tcp
        source: X.X.X.X/32
      '011 allow SSH from X.X.X.X/25':
        dport: 22
        proto: tcp
        source: X.X.X.X/25
      '012 allow SSH from X.X.X.X/24':
        dport: 22
        proto: tcp
        source: X.X.X.X/24
      '300 allow SNMP from NMS 1':
        dport: 161
        proto: udp
        source: X.X.X.X/24
      '301 allow SNMP from NMS 2':
        dport: 161
        proto: udp
        source: X.X.X.X/22
      '302 allow connection to Netdata':
        dport: 19999
      '303 allow Prometheus connections':
        dport: 9283
        proto: tcp
        source: X.X.X.X/22
```

### 报错
```
(overcloud) [stack@undercloud ~]$ aws s3 mb s3://dashboard
make_bucket failed: s3://dashboard Unable to parse response (not well-formed (invalid token): line 1, column 0), invalid XML received. Further retries may succeed:
b'{"entry_point_object_ver":{"tag":"_uSknuO-j1hIYKh1V_6uPxup","ver":1},"object_ver":{"tag":"_kFKbUVxpvcWgz4t71AqWZ2T","ver":1},"bucket_info":{"bucket":{"name":"dashboard","marker":"dd363c96-1c53-4ed7-9f92-b3c2766ef606.294168.1","bucket_id":"dd363c96-1c53-4ed7-9f92-b3c2766ef606.294168.1","tenant":"","explicit_placement":{"data_pool":"","data_extra_pool":"","index_pool":""}},"creation_time":"2021-12-01 07:03:45.758073Z","owner":"ceph-dashboard","flags":0,"zonegroup":"29d0675d-3ba5-452c-b6a7-64c0d9de3859","placement_rule":"default-placement","has_instance_obj":"true","quota":{"enabled":false,"check_on_raw":false,"max_size":-1,"max_size_kb":0,"max_objects":-1},"num_shards":11,"bi_shard_hash_type":0,"requester_pays":"false","has_website":"false","swift_versioning":"false","swift_ver_location":"","index_type":0,"mdsearch_config":[],"reshard_status":0,"new_bucket_instance_id":""}}'
```

### CephExternalMultiConfig 与 CinderRbdMultiConfig
Configuring Ceph Clients for Multiple External Ceph RBD Services<br>
CephExternalMultiConfig support was added in 16.1 specifically to support DCN topologies where
each site supports its own glance store.<br>
https://docs.openstack.org/project-deploy-guide/tripleo-docs/latest/features/ceph_external.html<br>

cinder support is currently not available. it's targeted for OSP-17. It will use a new CinderRbdMultiConfig THT parameter.<br>
https://bugzilla.redhat.com/show_bug.cgi?id=1949701<br>

### 部署单节点 rhcs 5 
```
# 参考
# https://docs.ceph.com/en/latest/man/8/cephadm/#bootstrap
cephadm bootstrap --single-host-defaults

# 安装虚拟机 jwang-ceph04
# rhel 8.4
# 如果之前未清理磁盘可以执行
# sgdisk --delete /dev/sda
# sgdisk --delete /dev/sdb
# sgdisk --delete /dev/sdc
# ks=http://10.66.208.115/jwang-ceph04-ks.cfg nameserver=10.64.63.6 ip=10.66.208.125::10.66.208.254:255.255.255.0:jwang-ceph04.example.com:ens3:none

# 生成 ks.cfg - jwang-ceph04
cat > jwang-ceph04-ks.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
halt
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
ignoredisk --only-use=sda
autopart
network --device=ens3 --hostname=jwang-ceph04.example.com --bootproto=static --ip=10.66.208.125 --netmask=255.255.255.0 --gateway=10.66.208.254 --nameserver=10.64.63.6
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
gdisk
openssl-perl
%end
EOF

# 注册系统到 rhn
subscription-manager register
subscription-manager refresh
subscription-manager list --available --matches 'Red Hat Ceph Storage'
subscription-manager attach --pool=8a85f99979908877017a0d85b3ab3c37
subscription-manager repos --disable=*
subscription-manager repos --enable=rhel-8-for-x86_64-baseos-rpms --enable=rhel-8-for-x86_64-appstream-rpms --enable=rhceph-5-tools-for-rhel-8-x86_64-rpms --enable=ansible-2.9-for-rhel-8-x86_64-rpms

# 同步 rhcs5 镜像
cat > syncimgs-rhcs5 <<'EOF'
#!/bin/env bash

PUSHREGISTRY=helper.example.com:5000
FORK=4

rhosp_namespace=registry.redhat.io/rhosp-rhel8
rhosp_tag=16.1
ceph_namespace=registry.redhat.io/rhceph
ceph_image=rhceph-5-rhel8
ceph_tag=latest
ceph_alertmanager_namespace=registry.redhat.io/openshift4
ceph_alertmanager_image=ose-prometheus-alertmanager
ceph_alertmanager_tag=v4.6
ceph_grafana_namespace=registry.redhat.io/rhceph
ceph_grafana_image=rhceph-5-dashboard-rhel8
ceph_grafana_tag=5
ceph_node_exporter_namespace=registry.redhat.io/openshift4
ceph_node_exporter_image=ose-prometheus-node-exporter
ceph_node_exporter_tag=v4.6
ceph_prometheus_namespace=registry.redhat.io/openshift4
ceph_prometheus_image=ose-prometheus
ceph_prometheus_tag=v4.6

function copyimg() {
  image=${1}
  version=${2}

  release=$(skopeo inspect docker://${image}:${version} | jq -r '.Labels | (.version + "-" + .release)')
  dest="${PUSHREGISTRY}/${image#*\/}"
  echo Copying ${image} to ${dest}
  skopeo copy docker://${image}:${release} docker://${dest}:${release} --quiet
  skopeo copy docker://${image}:${version} docker://${dest}:${version} --quiet
}

copyimg "${ceph_namespace}/${ceph_image}" ${ceph_tag} &
copyimg "${ceph_alertmanager_namespace}/${ceph_alertmanager_image}" ${ceph_alertmanager_tag} &
copyimg "${ceph_grafana_namespace}/${ceph_grafana_image}" ${ceph_grafana_tag} &
copyimg "${ceph_node_exporter_namespace}/${ceph_node_exporter_image}" ${ceph_node_exporter_tag} &
copyimg "${ceph_prometheus_namespace}/${ceph_prometheus_image}" ${ceph_prometheus_tag} &
wait

#for rhosp_image in $(podman search ${rhosp_namespace} --limit 1000 --format "{{ .Name }}"); do
#  ((i=i%FORK)); ((i++==0)) && wait
#  copyimg ${rhosp_image} ${rhosp_tag} &
#done
EOF

# rhcs5 软件仓库同步脚本
[root@helper repos]# pwd
/var/www/html/repos
[root@helper repos]# cat > rhcs5_repo_sync_up.sh <<EOF
#!/bin/bash

localPath="/var/www/html/repos/rhcs5/"
fileConn="/getPackage/"

## sync following yum repos 
# rhel-8-for-x86_64-baseos-rpms
# rhel-8-for-x86_64-appstream-rpms
# ansible-2.9-for-rhel-8-x86_64-rpms
# rhceph-5-tools-for-rhel-8-x86_64-rpms

for i in rhel-8-for-x86_64-baseos-rpms rhel-8-for-x86_64-appstream-rpms ansible-2.9-for-rhel-8-x86_64-rpms rhceph-5-tools-for-rhel-8-x86_64-rpms
do

  rm -rf "$localPath"$i/repodata
  echo "sync channel $i..."
  reposync -n --delete --download-path="$localPath" --repoid $i --downloadcomps --download-metadata

  #echo "create repo $i..."
  #time createrepo -g $(ls "$localPath"$i/repodata/*comps.xml) --update --skip-stat --cachedir /tmp/empty-cache-dir "$localPath"$i

done

exit 0
EOF

# 查看更新情况
watch "ls -ltr \$(ls -ltr | tail -1 | awk '{print \$9}')/\$(ls -ltr \$(ls -ltr | tail -1 | awk '{print \$9}') | tail -1 | awk '{print \$9}')"

# 在 ceph 节点上配置软件仓库
YUM_REPO_IP="10.66.208.121"
> /etc/yum.repos.d/local.repo 
for i in rhel-8-for-x86_64-baseos-eus-rpms rhel-8-for-x86_64-appstream-eus-rpms ansible-2.9-for-rhel-8-x86_64-rpms rhceph-5-tools-for-rhel-8-x86_64-rpms 
do
cat >> /etc/yum.repos.d/local.repo << EOF
[$i]
name=$i
baseurl=http://${YUM_REPO_IP}/repos/rhcs5/$i/
enabled=1
gpgcheck=0

EOF
done
# 使用本地 repo
> /etc/yum.repos.d/local.repo 
for i in rhel-8-for-x86_64-baseos-rpms rhel-8-for-x86_64-appstream-rpms ansible-2.9-for-rhel-8-x86_64-rpms rhceph-5-tools-for-rhel-8-x86_64-rpms 
do
cat >> /etc/yum.repos.d/local.repo << EOF
[$i]
name=$i
baseurl=file:///var/www/html/repos/rhcs5/$i/
enabled=1
gpgcheck=0

EOF
done


# 设置 /etc/hosts
sed -i '/jwang-ceph04.example.com/d' /etc/hosts
cat >> /etc/hosts <<EOF
10.66.208.125   jwang-ceph04.example.com    jwang-ceph04
EOF
cat >> /etc/hosts <<EOF
10.66.208.121   helper.example.com
EOF

# 更新系统
dnf makecache
dnf update -y

# 安装 cephadm
dnf install -y cephadm

# 安装 podman
dnf install -y podman

# 拷贝 local registry 证书
# 建立证书信任
[root@jwang-ceph04 ~]# scp 10.66.208.121:/opt/registry/certs/domain.crt /etc/pki/ca-trust/source/anchors 
domain.crt                                                                                               100% 2114   688.3KB/s   00:00    
[root@jwang-ceph04 ~]# update-ca-trust extract
# 登陆 local registry
[root@jwang-ceph04 ~]# podman login helper.example.com:5000 
Username: 
Password: 
Login Succeeded!

# 不需要执行
# 禁用 container-tools:rhel8 module 启用 container-tools:2.0 模块
# sudo dnf module disable -y container-tools:rhel8
# sudo dnf module enable -y container-tools:2.0

# 更新系统
dnf update -y

# 禁用 subscription-manager 
# subscription-manager config --rhsm.auto_enable_yum_plugins=0
# https://access.redhat.com/solutions/5838131

# 生成 ssh keypair 
ssh-keygen -t rsa -N '' -f /root/.ssh/id_rsa
ssh-copy-id 10.66.208.125 

# 使用本地镜像 
# 创建单节点集群
# https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html-single/installation_guide/index#configuring-a-custom-registry-for-disconnected-installation_install
# https://docs.ceph.com/en/latest/cephadm/install/
# 创建时可以为 bootstrap 传递初始配置文件
cat <<EOF > initial-ceph.conf
[global]
osd_crush_choose_leaf_type = 0
EOF
cephadm --image helper.example.com:5000/rhceph/rhceph-5-rhel8:latest bootstrap --config ./initial-ceph.conf --mon-ip 10.66.208.125 --allow-fqdn-hostname
# 目前看这种方法并不生效
cephadm shell
[ceph: root@jwang-ceph04 /]# ceph config set global osd_crush_chooseleaf_type 0
[ceph: root@jwang-ceph04 /]# ceph config dump
...
global        dev       osd_crush_chooseleaf_type              0                                                                                                                      * 
...
[ceph: root@jwang-ceph04 /]# ceph config set global osd_pool_default_size 1
[ceph: root@jwang-ceph04 /]# ceph config set global osd_pool_default_min_size 1

# 设置别名
echo "alias ceph='cephadm shell -- ceph'" >> ~/.bashrc
source ~/.bashrc

# 为节点打标签 mon
ceph orch host ls
ceph orch host label add jwang-ceph04.example.com mon

# 设置时间同步
sed -i 's|pool 2.rhel.pool.ntp.org iburst|server clock.corp.redhat.com iburst|' /etc/chrony.conf
systemctl restart chronyd
chronyc -n sources

# 查看可用设备
ceph orch device ls --refresh

# 手工添加设备
ceph orch daemon add osd jwang-ceph04.example.com:/dev/sdb
ceph orch daemon add osd jwang-ceph04.example.com:/dev/sdc
ceph orch daemon add osd jwang-ceph04.example.com:/dev/sdd

# 告警，后续分析
WARNING: The same type, major and minor should not be used for multiple devices.
WARNING: The same type, major and minor should not be used for multiple devices.

[ceph: root@jwang-ceph04 /]# ceph health detail 
HEALTH_WARN 1 failed cephadm daemon(s); Reduced data availability: 1 pg inactive; Degraded data redundancy: 1 pg undersized
[WRN] CEPHADM_FAILED_DAEMON: 1 failed cephadm daemon(s)
    daemon node-exporter.jwang-ceph04 on jwang-ceph04.example.com is in error state
[WRN] PG_AVAILABILITY: Reduced data availability: 1 pg inactive
    pg 1.0 is stuck inactive for 5m, current state undersized+peered, last acting [1]
[WRN] PG_DEGRADED: Degraded data redundancy: 1 pg undersized
    pg 1.0 is stuck undersized for 5m, current state undersized+peered, last acting [1]

# 获取 pool 的信息
[ceph: root@jwang-ceph04 /]# ceph osd dump | grep pool 
pool 1 'device_health_metrics' replicated size 3 min_size 2 crush_rule 0 object_hash rjenkins pg_num 1 pgp_num 1 autoscale_mode on last_change 22 flags hashpspool stripe_width 0 pg_num_min 1 application mgr_devicehealth
# 设置 pool 的 min_size
[ceph: root@jwang-ceph04 /]# ceph osd pool set device_health_metrics min_size 1 
set pool 1 min_size to 1

[ceph: root@jwang-ceph04 /]# ceph osd dump | grep pool 
pool 1 'device_health_metrics' replicated size 3 min_size 1 crush_rule 0 object_hash rjenkins pg_num 1 pgp_num 1 autoscale_mode on last_change 23 flags hashpspool stripe_width 0 pg_num_min 1 application mgr_devicehealth

# 检查 ceph 的 health 状态
[ceph: root@jwang-ceph04 /]# ceph health detail        
HEALTH_WARN 1 failed cephadm daemon(s)
[WRN] CEPHADM_FAILED_DAEMON: 1 failed cephadm daemon(s)
    daemon node-exporter.jwang-ceph04 on jwang-ceph04.example.com is in error state

# 为节点打标签 osd
ceph orch host label add jwang-ceph04.example.com osd

# 关于 failed cephadm daemon(s)
# 原因是在节点上的 node-exporter 无法启动
# 检查 node-exporter unit 文件内容
[root@jwang-ceph04 ~]# cat /var/lib/ceph/0c1839ae-5349-11ec-9989-001a4a16016f/node-exporter.jwang-ceph04/unit.run 
set -e
# node-exporter.jwang-ceph04
! /bin/podman rm -f ceph-0c1839ae-5349-11ec-9989-001a4a16016f-node-exporter.jwang-ceph04 2> /dev/null
! /bin/podman rm -f ceph-0c1839ae-5349-11ec-9989-001a4a16016f-node-exporter-jwang-ceph04 2> /dev/null
! /bin/podman rm -f --storage ceph-0c1839ae-5349-11ec-9989-001a4a16016f-node-exporter-jwang-ceph04 2> /dev/null
! /bin/podman rm -f --storage ceph-0c1839ae-5349-11ec-9989-001a4a16016f-node-exporter.jwang-ceph04 2> /dev/null
/bin/podman run --rm --ipc=host --net=host --init --name ceph-0c1839ae-5349-11ec-9989-001a4a16016f-node-exporter-jwang-ceph04 --user 65534 -d --log-driver journald --conmon-pidfile /run/ceph-0c1839ae-5349-11ec-9989-001a4a16016f@node-exporter.jwang-ceph04.service-pid --cidfile /run/ceph-0c1839ae-5349-11ec-9989-001a4a16016f@node-exporter.jwang-ceph04.service-cid -e CONTAINER_IMAGE=registry.redhat.io/openshift4/ose-prometheus-node-exporter:v4.6 -e NODE_NAME=jwang-ceph04.example.com -e CEPH_USE_RANDOM_NONCE=1 -e TCMALLOC_MAX_TOTAL_THREAD_CACHE_BYTES=134217728 -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /:/rootfs:ro registry.redhat.io/openshift4/ose-prometheus-node-exporter:v4.6 --no-collector.timex

# 解决方法是在对应节点上手工执行 podman pull 和 podman tag
[root@jwang-ceph04 ~]# podman pull helper.example.com:5000/openshift4/ose-prometheus-node-exporter:v4.6
[root@jwang-ceph04 ~]# podman tag helper.example.com:5000/openshift4/ose-prometheus-node-exporter:v4.6 registry.redhat.io/openshift4/ose-prometheus-node-exporter:v4.6

# 为节点打标签 mds
ceph orch host label add jwang-ceph04.example.com mds
# 看看 cephfs mds 服务
ceph fs volume create cephfs
ceph orch apply mds cephfs --placement="2 jwang-ceph04.example.com jwang-ceph04.example.com"

# rhcs5 purge/remove cluster
# https://bugzilla.redhat.com/show_bug.cgi?id=1881192

# ceph status
# insufficient standby MDS daemons available
# Degraded data redundancy: 30/56 objects degraded (53.571%), 14 pgs degraded, 65 pgs undersized
# fsid 是通过 ceph status 获取到的
#   cluster:
#   id:     0c1839ae-5349-11ec-9989-001a4a16016f
[root@jwang-ceph04 ~]# cephadm rm-cluster --fsid 0c1839ae-5349-11ec-9989-001a4a16016f --force

# 部署完的信息
Ceph Dashboard is now available at:

             URL: https://jwang-ceph04.example.com:8443/
            User: admin
        Password: rvg20bg7zv

You can access the Ceph CLI with:

        sudo /usr/sbin/cephadm shell --fsid 88946910-53f0-11ec-ab5a-001a4a16016f -c /etc/ceph/ceph.conf -k /etc/ceph/ceph.client.admin.keyring

Please consider enabling telemetry to help improve Ceph:

        ceph telemetry on

For more information see:

        https://docs.ceph.com/docs/pacific/mgr/telemetry/

# 通过改 crush 设置 single node cluster
# https://linoxide.com/hwto-configure-single-node-ceph-cluster/

# 清理节点上的 osd 磁盘 device mapper
# https://www.cnblogs.com/deny/p/14214963.html
# 查看磁盘
dmsetup ls

# 删除磁盘
dmsetup remove ceph--d534c556--1abd--4739--94c8--4c6fa8bfe12c-osd--block--65634030--05cd--4305--b08a--6bd8c43d8c76
rm -f /dev/mapper/ceph--d534c556--1abd--4739--94c8--4c6fa8bfe12c-osd--block--65634030--05cd--4305--b08a--6bd8c43d8c76

dmsetup remove ceph--55676940--281c--43fc--9b71--d359acecb778-osd--block--e0b08b95--d184--4dd8--9748--e495c5225caa
rm -f /dev/mapper/ceph--55676940--281c--43fc--9b71--d359acecb778-osd--block--e0b08b95--d184--4dd8--9748--e495c5225caa

dmsetup remove ceph--9cb74522--f080--4e25--a6fa--3b6b8a893444-osd--block--82b96e58--bb69--4492--a320--993a963890c6
rm -f /dev/mapper/ceph--9cb74522--f080--4e25--a6fa--3b6b8a893444-osd--block--82b96e58--bb69--4492--a320--993a963890c6

# 查看 device-mapper 设备
[root@jwang-ceph04 ~]# dmsetup ls
rhel_jwang--ceph04-home (253:2)
ceph--5c2ef1ac--2a33--42e7--bc7c--96aec8a2550b-osd--block--5ece89a4--cabb--4d7a--8b8b--c7baa75a1cb6     (253:3)
ceph--31c8737c--4ec0--49ea--b26b--e733989461c3-osd--block--fded4dd6--696e--43df--9247--8df0cd161ce5     (253:5)
rhel_jwang--ceph04-swap (253:1)
rhel_jwang--ceph04-root (253:0)
ceph--20632c65--91ac--4924--849b--f54e392a3999-osd--block--6be9216c--153d--4959--b818--498c1e1f79b4     (253:4)
# 移除 device-mapper 设备
[root@jwang-ceph04 ~]# mkdir -p /root/backup
[root@jwang-ceph04 ~]# mv /dev/dm-3 /root/backup/
[root@jwang-ceph04 ~]# mv /dev/dm-4 /root/backup/
[root@jwang-ceph04 ~]# mv /dev/dm-5 /root/backup/

# 报错
# WARNING: The same type, major and minor should not be used for multiple devices.
# https://tracker.ceph.com/issues/51668


[root@jwang-ceph04 ~]# ceph health detail 
Inferring fsid a31452c6-53f2-11ec-a115-001a4a16016f
Inferring config /var/lib/ceph/a31452c6-53f2-11ec-a115-001a4a16016f/mon.jwang-ceph04.example.com/config
Using recent ceph image helper.example.com:5000/rhceph/rhceph-5-rhel8@sha256:7f374a6e1e8af2781a19a37146883597e7a422160ee86219ce6a5117e05a1682
...
HEALTH_WARN 1 pool(s) have no replicas configured
[WRN] POOL_NO_REDUNDANCY: 1 pool(s) have no replicas configured
    pool 'device_health_metrics' has no replicas configured

HEALTH_WARN insufficient standby MDS daemons available
[WRN] MDS_INSUFFICIENT_STANDBY: insufficient standby MDS daemons available
    have 0; want 1 more

ceph fs ls
ceph mds stat
ceph fs status 
ceph health detail
# 部署 nfs ganesha daemon
# https://docs.ceph.com/en/pacific/cephadm/services/nfs/

# 生成 cephfs client authorize
ceph fs authorize cephfs client.cephfs.1 / rw
# 注意创建适合的 keyring 文件
ceph auth get client.cephfs.1 > /etc/ceph/keyring
mkdir /tmp/cephfs
# 安装 cephfs 客户端
yum install ceph-common
yum install ceph-fuse
# 通过 ceph-fuse 挂载 cephfs
ceph-fuse -n client.cephfs.1 -m jwang-ceph04:6789 --keyring=/etc/ceph/keyring /tmp/cephfs
# 通过 kernel client 挂载 cephfs
# 注意创建适合的 secret 文件
ceph auth get-key client.cephfs.1 > /etc/ceph/secret
# https://docs.ceph.com/en/latest/cephfs/mount-using-kernel-driver/#which-kernel-version
mount -t ceph 10.66.208.125:6789:/ /tmp/cephfs -o name=cephfs.1,secretfile=/etc/ceph/secret

# 部署 rgw 服务
ceph orch host label add jwang-ceph04.example.com rgw
ceph orch apply rgw default default --placement='1 jwang-ceph04.example.com'

# 创建证书
[root@jwang-ceph04 ~]# mkdir -p /opt/rgw/certs
[root@jwang-ceph04 ~]# cd /opt/rgw/certs
[root@jwang-ceph04 certs]# openssl req -newkey rsa:4096 -nodes -sha256 -keyout domain.key -x509 -days 3650 -out domain.crt  -addext "subjectAltName = DNS:jwang-ceph04.example.com" -subj "/C=CN/ST=GD/L=SZ/O=Global Security/OU=IT Department/CN=jwang-ceph04.example.com"
[root@jwang-ceph04 certs]# cp /opt/rgw/certs/domain.crt /etc/pki/ca-trust/source/anchors/
[root@jwang-ceph04 certs]# update-ca-trust extract
# 参考：https://greenstatic.dev/posts/2020/ssl-tls-rgw-ceph-config/
[root@jwang-ceph04 ~]# cephadm shell
[ceph: root@jwang-ceph04 /]# mkdir -p /opt/rgw/certs

# 回到主机，找到 cephadm shell 对应的 pod id
[root@jwang-ceph04 ~]# podman ps | grep ceph
...
5f9feddeb888  helper.example.com:5000/rhceph/rhceph-5-rhel8@sha256:7f374a6e1e8af2781a19a37146883597e7a422160ee86219ce6a5117e05a1682  -F -L STDERR -N N...  3 days ago     Up 3 days ago                 ceph-a31452c6-53f2-11ec-a115-001a4a16016f-nfs-nfs1-jwang-ceph04
eb37459b8812  helper.example.com:5000/rhceph/rhceph-5-rhel8@sha256:7f374a6e1e8af2781a19a37146883597e7a422160ee86219ce6a5117e05a1682                        3 minutes ago  Up 3 minutes ago              interesting_poincare
[root@jwang-ceph04 ~]# podman cp /opt/rgw/certs/. eb37459b8812:/opt/rgw/certs

# 回到 cephadm shell 容器
# https://greenstatic.dev/posts/2020/ssl-tls-rgw-ceph-config/
# https://lists.ceph.io/hyperkitty/list/ceph-users@ceph.io/thread/ATIT67EMNE6VBNESBJO4JCIVCJ7Y75Q4/
[ceph: root@jwang-ceph04 /]# ceph config-key set rgw/cert//default.crt -i /opt/rgw/certs/domain.crt
[ceph: root@jwang-ceph04 /]# ceph config-key set rgw/cert//default.key -i /opt/rgw/certs/domain.key
[ceph: root@jwang-ceph04 /]# ceph config dump | grep rgw_frontends
[ceph: root@jwang-ceph04 /]# ceph config set client.rgw.default.default rgw_frontends "beast port=80 ssl_port=443 ssl_certificate=config://rgw/cert//default.crt ssl_private_key=config://rgw/cert//default.key"
[ceph: root@jwang-ceph04 /]# ceph config set client.rgw.default.jwang-ceph04.gscijv rgw_frontends "beast port=80 ssl_port=443 ssl_certificate=config://rgw/cert//default.crt ssl_private_key=config://rgw/cert//default.key"
[ceph: root@jwang-ceph04 /]# ceph config dump | grep rgw_frontends

# 从 aws 客户端访问 rgw s3 服务
[root@jwang-ceph04 ~]# export AWS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
[root@jwang-ceph04 ~]# aws --endpoint=https://jwang-ceph04.example.com:443 s3 ls
2021-12-06 13:50:00 test

# 添加 https 到防火墙
[root@jwang-ceph04 ~]# firewall-cmd --add-service=https --permanent
[root@jwang-ceph04 ~]# firewall-cmd --reload

# 查看 ceph config-key rgw/cert//default.crt 与 rgw/cert//default.key
[ceph: root@jwang-ceph04 /]# ceph config-key get rgw/cert//default.crt
[ceph: root@jwang-ceph04 /]# ceph config-key get rgw/cert//default.key
[ceph: root@jwang-ceph04 /]# ceph config get client.rgw.default.jwang-ceph04.gscijv.rgw_frontends 


# 回到 ceph 主机
# 查看 ceph 服务
[root@jwang-ceph04 ~]# ceph orch ls
# 重启 rgw.default
[root@jwang-ceph04 ~]# ceph orch restart rgw.default

# 下载镜像并且tag镜像
# 需要在每个节点上做一遍
[root@jwang-ceph04 rhcs5]# podman pull helper.example.com:5000/openshift4/ose-prometheus:v4.6
[root@jwang-ceph04 rhcs5]# podman tag helper.example.com:5000/openshift4/ose-prometheus:v4.6 registry.redhat.io/openshift4/ose-prometheus:v4.6
[root@jwang-ceph04 rhcs5]# podman pull helper.example.com:5000/openshift4/ose-prometheus-alertmanager:v4.6
[root@jwang-ceph04 rhcs5]# podman tag helper.example.com:5000/openshift4/ose-prometheus-alertmanager:v4.6 registry.redhat.io/openshift4/ose-prometheus-alertmanager:v4.6
[root@jwang-ceph04 rhcs5]# podman pull helper.example.com:5000/rhceph/rhceph-5-dashboard-rhel8:5 
[root@jwang-ceph04 rhcs5]# podman tag helper.example.com:5000/rhceph/rhceph-5-dashboard-rhel8:5 registry.redhat.io/rhceph/rhceph-5-dashboard-rhel8:5
[root@jwang-ceph04 rhcs5]# podman tag helper.example.com:5000/rhceph/rhceph-5-dashboard-rhel8:5 registry.redhat.io/rhceph/rhceph-5-dashboard-rhel8:latest

# 更改 ceph dashboard admin password
echo -n "p@ssw0rd" > password.txt
# ceph dashboard ac-user-create admin -i password.txt administrator
ceph dashboard ac-user-set-password admin -i password.txt 

# 把 ceph dashboard 和 rgw 集成起来
# https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html-single/dashboard_guide/index#management-of-ceph-object-gateway-using-the-dashboard
radosgw-admin user create --uid=test_user --display-name=TEST_USER --system
radosgw-admin user info --uid test_user
echo -n $(radosgw-admin user info --uid test_user | grep access_key | awk '{print $2}' | sed -e 's|"||g' -e 's|,$||') > access_key
echo -n $(radosgw-admin user info --uid test_user | grep secret_key | awk '{print $2}' | sed -e 's|"||g' -e 's|,$||')  > secret_key
ceph dashboard set-rgw-api-access-key -i access_key
ceph dashboard set-rgw-api-secret-key -i secret_key
ceph dashboard set-rgw-api-host 10.66.208.125
ceph dashboard set-rgw-api-port 80

# 查看 ceph dashboard feature
ceph dashboard feature status

# 部署 nfs 服务
# https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html-single/dashboard_guide/index#management-of-nfs-ganesha-exports-on-the-ceph-dashboard
[ceph: root@jwang-ceph04 /]# ceph osd pool create nfs_ganesha 32 32 
pool 'nfs_ganesha' created
[ceph: root@jwang-ceph04 /]# ceph osd dump | grep pool


ceph osd pool create nfs_ganesha
ceph osd pool application enable nfs_ganesha rgw
ceph orch apply nfs nfs1 --pool nfs_ganesha --namespace nfs-ns --placement="1 jwang-ceph04.example.com"
ceph dashboard set-ganesha-clusters-rados-pool-namespace nfs_ganesha/nfs1

[root@jwang-ceph04 ~]# ceph dashboard set-ganesha-clusters-rados-pool-namespace nfs_ganesha/nfs1
Option GANESHA_CLUSTERS_RADOS_POOL_NAMESPACE updated

# 配置 nfs export object gateway
# https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html-single/dashboard_guide/index#management-of-nfs-ganesha-exports-on-the-ceph-dashboard
# https://docs.google.com/document/d/1DxS3oKsBvzgcYmnERfoIpULcJVmpPG0rIzMSgRgFL24/edit?usp=sharing

[ceph: root@jwang-ceph04 /]# ceph status
  cluster:
    id:     a31452c6-53f2-11ec-a115-001a4a16016f
    health: HEALTH_WARN
            insufficient standby MDS daemons available
 
  services:
    mon:     1 daemons, quorum jwang-ceph04.example.com (age 2d)
    mgr:     jwang-ceph04.example.com.myares(active, since 3d)
    mds:     1/1 daemons up
    osd:     3 osds: 3 up (since 2d), 3 in (since 2d)
    rgw:     1 daemon active (1 hosts, 1 zones)
    rgw-nfs: 1 daemon active (1 hosts, 1 zones)
 
  data:
    volumes: 1/1 healthy
    pools:   8 pools, 201 pgs
    objects: 253 objects, 7.9 KiB
    usage:   69 MiB used, 30 GiB / 30 GiB avail
    pgs:     201 active+clean
 
  io:
    client:   7.2 KiB/s rd, 170 B/s wr, 8 op/s rd, 2 op/s wr

# 安装 nfs 客户端
[root@jwang-ceph04 ~]# yum install -y nfs-utils 
[root@jwang-ceph04 ~]# mkdir -p /tmp/nfs
[root@jwang-ceph04 ~]# mount -t nfs 10.66.208.125:/test /tmp/nfs
[root@jwang-ceph04 ~]# mount | grep nfs
10.66.208.125:/ on /tmp/nfs type nfs4 (rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.66.208.125,local_lock=none,addr=10.66.208.125)
[root@jwang-ceph04 ~]# cd /tmp/nfs

# podman exec -it <nfspod> bash
# 编辑 /etc/ganesha/ganesha.conf
# 把 Protocols 改为 3,4
# 添加 Bind_Addr 
NFS_CORE_PARAM {
        Enable_NLM = false;
        Enable_RQUOTA = false;
        Bind_Addr = 10.66.208.125;
        Protocols = 3,4;
}
# 退出 nfspod，重启 nfs 服务
systemctl restart ceph-a31452c6-53f2-11ec-a115-001a4a16016f@nfs.nfs1.jwang-ceph04.service
systemctl status ceph-a31452c6-53f2-11ec-a115-001a4a16016f@nfs.nfs1.jwang-ceph04.service

# 挂载 nfsver3 
# 为 firewall 添加 mountd port
# 每次重启 nfs ganesha mountd port 都会改变
[root@jwang-ceph04 ~]# rpcinfo -p 10.66.208.125 | grep -E " 3 " | grep -E "tcp"
    100000    3   tcp    111  portmapper
    100003    3   tcp   2049  nfs
    100005    3   tcp  38733  mountd
[root@jwang-ceph04 ~]# firewall-cmd 
firewall-cmd --add-port=38733/tcp --permanent
firewall-cmd --add-port=57897/tcp --permanent

# mountd 的 tcp 端口每次都改变如何处理
# https://www.ibm.com/support/pages/how-force-mountdlockd-use-specific-port

firewall-cmd --reload
mount -t nfs -o nfsvers=3,proto=tcp,noacl 10.66.208.125:/test /tmp/nfs 
mount -t nfs -vvvv 10.66.208.125:/test /tmp/nfs 
mount -t nfs -o nfsvers=3,proto=tcp -vvvv 10.66.208.125:/test /tmp/nfs 

# nfs-ganesha 日志
# https://documentation.suse.com/ses/7/html/ses-all/bp-troubleshooting-nfs.html
# 获取 fsid 
# [root@jwang-ceph04 ~]# cephadm ls | grep fsid 
# 获取 instance name
# [root@jwang-ceph04 ~]# cephadm ls | grep name 
[root@jwang-ceph04 ~]# cephadm logs --fsid a31452c6-53f2-11ec-a115-001a4a16016f --name nfs.nfs1.jwang-ceph04 

# 登陆 nfs pod
# 修改 /etc/ganesha/ganesha.conf 
LOG {   
        COMPONENTS {
                ALL=FULL_DEBUG;
        }
}
# 重启 nfs ganesha 服务 

# 报错
mount.nfs: access denied by server while mounting 10.66.208.125:/test
# 社区文档 radosgw + nfs ganesha
# https://docs.ceph.com/en/latest/radosgw/nfs/

cephadm shell
# %url    rados://nfs_ganesha/nfs-ns/conf-nfs.nfs1
# rados -p nfs_ganesha -N nfs-ns get conf-nfs.nfs1 -
# %url "rados://nfs_ganesha/nfs-ns/export-1"
# rados -p nfs_ganesha -N nfs-ns get export-1 -
[ceph: root@jwang-ceph04 /]# rados -p nfs_ganesha -N nfs-ns get export-1 -
EXPORT {
    export_id = 1;
    path = "test";
    pseudo = "/test";
    access_type = "RW";
    squash = "no_root_squash";
    protocols = 4;
    transports = "TCP";
    FSAL {
        name = "RGW";
        user_id = "test_user";
        access_key_id = "JKT0TCBHNQPAZ8BGH9SP";
        secret_access_key = "aBm3DNOwicyhgy9EBNTWLISQBvZeJgNA5ArUTp1K";
    }

}
# 更新这个对象, protocols 为 3,4
[ceph: root@jwang-ceph04 /]# cat > export-1 <<EOF
EXPORT {
    export_id = 1;
    path = "test";
    pseudo = "/test";
    access_type = "RW";
    squash = "no_root_squash";
    protocols = 3,4;
    transports = "TCP";
    FSAL {
        name = "RGW";
        user_id = "test_user";
        access_key_id = "JKT0TCBHNQPAZ8BGH9SP";
        secret_access_key = "aBm3DNOwicyhgy9EBNTWLISQBvZeJgNA5ArUTp1K";
    }

}
EOF
[ceph: root@jwang-ceph04 /]# rados -p nfs_ganesha -N nfs-ns put export-1 export-1
# 检查更新
[ceph: root@jwang-ceph04 /]# rados -p nfs_ganesha -N nfs-ns get export-1 -

# 重启 nfs ganesha
[root@jwang-ceph04 ~]# systemctl restart ceph-a31452c6-53f2-11ec-a115-001a4a16016f@nfs.nfs1.jwang-ceph04.service 
# 添加 nfs version3 防火墙规则
firewall-cmd --add-service={nfs3,mountd,rpc-bind} --permanent 
firewall-cmd --reload

# 报错
[root@jwang-ceph04 ~]# mount -t nfs -o nfsvers=3 10.66.208.125:/test /tmp/nfs
...
mount.nfs: access denied by server while mounting 10.66.208.125:/test

# rpcinfo 显示 nfs vers 3 是存在的
[root@jwang-ceph04 ~]# rpcinfo -p 10.66.208.125 | grep " 3 " 
    100000    3   tcp    111  portmapper
    100000    3   udp    111  portmapper
    100003    3   udp   2049  nfs
    100003    3   tcp   2049  nfs
    100005    3   udp  59743  mountd
    100005    3   tcp  35325  mountd

# 报错
mnt_Mnt :NFS3 :INFO :MOUNT: Export entry / does not support NFS v3
# http://lists.ceph.com/pipermail/ceph-users-ceph.com/2018-June/027675.html
# https://access.redhat.com/documentation/zh-cn/red_hat_ceph_storage/3/html/object_gateway_guide_for_ubuntu/exporting-the-namespace-to-nfs-ganesha-rgw
# 登陆 nfs pod
# 修改 /etc/ganesha/ganesha.conf 
# 在 NFS_CORE_PARAM 里添加 mount_path_pseudo
NFS_CORE_PARAM {
        Enable_NLM = false;
        Enable_RQUOTA = false;
        Bind_Addr = 10.66.208.125;
        Protocols = 3,4;
        mount_path_pseudo = true;
}
# 重启 nfs ganesha 服务
# 这次可以用 nfsvers=3 加载 nfs ganesha 共享了
mount -t nfs -o nfsvers=3,proto=tcp -vvvv 10.66.208.125:/test /tmp/nfs 

# 报错
overlayfs: unrecognized mount option "volatile" or missing value
touch: setting times of 'a': No such file or directory

# 用 s3 上传文件后
# nfs 加载可以拷贝文件并且创建文件了

# 根据 ceph orch ls 的输出调整 mon 和 mgr 的 placement
ceph orch ls
ceph orch apply mon --placement="1 jwang-ceph04.example.com"
ceph orch apply mgr --placement="1 jwang-ceph04.example.com"

# 设置 ceph fs 需要的 standby mds 的数量
ceph fs ls
ceph fs set cephfs standby_count_wanted 0
# 尝试在 single node 上起两个 mds 实例，上面的命令生效了，无需执行
# ceph orch apply mds cephfs --placement="2 jwang-ceph04.example.com jwang-ceph04.example.com"

# Window 10 nfs 文件
# https://blog.csdn.net/qq_34158598/article/details/81976063
# https://kenvix.com/post/win10-mount-nfs/
# https://blog.csdn.net/a603423130/article/details/100139226
# https://jermsmit.com/mount-nfs-share-in-windows-10/
# Win_R: OptionalFeatures 
# 以下命令在 Window 10 Education 版上无需执行
# Dism /online /Get-Features
# Dism /online /Enable-Feature:NFS-Administration
# https://blog.csdn.net/liuqun69/article/details/82457617
# https://cloud.tencent.com/developer/article/1840455
# 重启 nfs client
# nfsadmin client stop
# nfsadmin client start
# https://docs.datafabric.hpe.com/62/AdministratorGuide/MountingNFSonWindowsClient.html
# ERROR: Unsupported Windows Version
# https://graspingtech.com/mount-nfs-share-windows-10/
# https://github.com/nfs-ganesha/nfs-ganesha/issues/281
# 为了让 windows nfs client 工作，需要先用 linux 客户端使用 nfs v3 mount 加载 nfs export
# 08/12/2021 03:55:57 : epoch 61b02c72 : jwang-ceph04.example.com : ganesha.nfsd-6[reaper] rados_cluster_end_grace :CLIENT ID :EVENT :Failed to remove rec-0000000000000007:nfs.nfs1.jwang-ceph04: -2
# 08/12/2021 03:55:57 : epoch 61b02c72 : jwang-ceph04.example.com : ganesha.nfsd-6[reaper] nfs_lift_grace_locked :STATE :EVENT :NFS Server Now NOT IN GRACE
# 尝试用 nfs-win
# https://github.com/billziss-gh/nfs-win
net use x: "\\nfs\test=0.0@10.66.208.125\test"
# 尝试用 fuse-nfs +  dokany
# https://github.com/Daniel-Abrecht/fuse-nfs-crossbuild-scripts/
# https://github.com/dokan-dev/dokany
# fuse-nfs.exec -D -n nfs://10.66.208.121/srv/nfs4 -m 'X:'
# Dokan Error: DokanMount Failed
# Ioctl failed with waif for code 995
# 经过测试，支持命令是
# fuse-nfs.exec -D -n nfs://10.66.208.121/srv/nfs4 -m X
# 加载 nfs-ganesha pseudo path mount
# https://github.com/sahlberg/fuse-nfs
# fuse-nfs.exec -D -u 0 -g 0 -r -n nfs://10.66.208.125/test?version=4 -m P

# 为了兼容 fuse-nfs.exe 的 libnfs version=4
# 登陆 nfs pod
# 修改 /etc/ganesha/ganesha.conf 
# 在 NFSv4 Minor_Versions 里 0
NFSv4 { 
        Delegations = false;
        RecoveryBackend = 'rados_cluster';
        Minor_Versions = 0, 1, 2;
}
# 重启 nfs pod
# 测试的情况是 fuse-nfs.exe 不稳定
# https://blog.csdn.net/qq_25675517/article/details/112339045
# NFSClient 是 ms-nfs41-client
# https://cloud.tencent.com/developer/article/1605657
# NFSClient 使用 v4.1 协议目前看效果还行

cephadm shell
[ceph: root@jwang-ceph04 /]# ceph mgr module enable nfs
[ceph: root@jwang-ceph04 /]# ceph nfs cluster info nfs1 
{
    "nfs1": [
        {
            "hostname": "jwang-ceph04.example.com",
            "ip": "10.66.208.125",
            "port": 2049
        }
    ]
}

# 日志报错
# Dec 09 09:39:26 jwang-ceph04.example.com conmon[1848901]: level=error ts=2021-12-09T01:39:26.452Z caller=dispatch.go:309 component=dispatcher msg="Notify for alerts failed" num_alerts=1 err="ceph-dashboard/webhook[0]: notify retry canceled after 7 attempts: Post \"https://10.66.208.125:8443/api/prometheus_receiver\": x509: cannot validate certificate for 10.66.208.125 because it doesn't contain any IP SANs"
# https://github.com/prometheus/prometheus/issues/1654

# systemctl -l | grep prom
# alert manager 的配置文件也在 /var/lib/ceph/a31452c6-53f2-11ec-a115-001a4a16016f/ 下
# /var/lib/ceph/a31452c6-53f2-11ec-a115-001a4a16016f/alertmanager.jwang-ceph04/etc/alertmanager/alertmanager.yml
# 添加 http_config: tls_config: insecure_skip_verify: true
global:
  resolve_timeout: 5m
  http_config:
    tls_config:
      insecure_skip_verify: true
# 重启 alertmanager service

[root@jwang-ceph04 ~]# systemctl status ceph-a31452c6-53f2-11ec-a115-001a4a16016f@prometheus.jwang-ceph04.service 
 ceph-a31452c6-53f2-11ec-a115-001a4a16016f@prometheus.jwang-ceph04.service - Ceph prometheus.jwang-ceph04 for a31452c6-53f2-11ec-a115-001>
   Loaded: loaded (/etc/systemd/system/ceph-a31452c6-53f2-11ec-a115-001a4a16016f@.service; enabled; vendor preset: disabled)
   Active: active (running) since Thu 2021-12-09 10:33:57 CST; 3h 29min ago
  Process: 2411084 ExecStopPost=/bin/rm -f //run/ceph-a31452c6-53f2-11ec-a115-001a4a16016f@prometheus.jwang-ceph04.service-pid //run/ceph->
  Process: 2411083 ExecStopPost=/bin/bash /var/lib/ceph/a31452c6-53f2-11ec-a115-001a4a16016f/prometheus.jwang-ceph04/unit.poststop (code=e>
  Process: 2410974 ExecStop=/bin/bash -c /bin/podman stop ceph-a31452c6-53f2-11ec-a115-001a4a16016f-prometheus.jwang-ceph04 ; bash /var/li>
  Process: 2411088 ExecStart=/bin/bash /var/lib/ceph/a31452c6-53f2-11ec-a115-001a4a16016f/prometheus.jwang-ceph04/unit.run (code=exited, s>
  Process: 2411086 ExecStartPre=/bin/rm -f //run/ceph-a31452c6-53f2-11ec-a115-001a4a16016f@prometheus.jwang-ceph04.service-pid //run/ceph->
 Main PID: 2411209 (conmon)



# 设置 dashboard set-prometheus-api-ssl-verify 
# https://docs.ceph.com/en/latest/api/mon_command_api/
ceph dashboard set-prometheus-api-ssl-verify false
ceph orch rm prometheus
ceph orch apply prometheus

# 设置防火墙
# https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/5/html/configuration_guide/ceph-network-configuration
# Mon
[root@jwang-ceph04 ~]# firewall-cmd --zone=public --add-port=6789/tcp --permanent
[root@jwang-ceph04 ~]# firewall-cmd --zone=public --add-port=3300/tcp --permanent
# OSDs and MDS
[root@jwang-ceph04 ~]# firewall-cmd --zone=public --add-port=6800-6830/tcp --permanent
[root@jwang-ceph04 ~]# firewall-cmd --reload


```

### Windows 11 and KVM
https://getlabsdone.com/how-to-install-windows-11-on-kvm/<br>
https://blogs.ovirt.org/wp-content/uploads/2021/09/05-TPM-support-in-oVirt-Milan-Zamazal-Tomas-Golembiovsky.pdf<br>

### 用 openssl s_client 命令检查站点是否支持 TLSv1 和 SSLv3 
```
# 出于安全的考量 TLSv1 和 SSLv3 应该关闭
# echo|openssl s_client -connect xx.xxx.xx.xx:8443 -ssl3 2>/dev/null|grep -e 'Secure Renegotiation IS' -e 'Cipher is ' -e 'Protocol :'
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-SHA
Secure Renegotiation IS supported
 Protocol : SSLv3
# echo|openssl s_client -connect xx.xxx.xx.xx:8443 -tls1 2>/dev/null|grep -e 'Secure Renegotiation IS' -e 'Cipher is ' -e 'Protocol :'
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-SHA
Secure Renegotiation IS supported
 Protocol : TLSv1
```

### 手工生成 kubeconfig 的方法
```
# log in on the web console and select youruser > get login command
# authenticate with your user/password and click “display token”, copy the API URL and token values from there.
### replace dots with dashes on the FQDN of your API host in the following commands, EXCEPT when it is an actual URL (argument to --server)
### replace apihostfqdn, port, youruser, project, and tokenfromwebconsole with values that match your cluster

### kubectl does not require that you use those long and redundant keys, not requires that the key of a context matches the name of the project and so on, but this is how oc commands set the kubeconfig file so if you follow its conventions you should be able to switch from kubectl to oc and vice-versa if you need.
$ kubectl config set-cluster apihostfqdn:port --server=https://apihostfqdn:port
$ kubectl config set-credentials youruser/apihostfqdn:port --token=tokenfromwebconsole
$ kubectl config set-context project/apihostfqdn:port/youruser --cluster=apihostfqdn:port --user=youruser/apihostfqdn:port --namespace=project
$ kubectl config use-context project/apihostfqdn:port:6443/youruser
```

### CentOS 在 UEFI 部署下兼容 BIOS 启动的步骤
```
# yum -y install grub2-pc
# grub2-mkconfig -o /boot/grub2/grub.cfg
# grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
# grub2-install --force --target=i386-pc /dev/vda

# in order to change the boot from UEFI to BIOS, you would also need to make sure that the boot loader 
# is installed to the master boot record (on MBR systems) or create a BIOS boot partition (on GPT systems).
```

### CentOS 8 上的 nfsd 默认启用 v3, v4, v4.1 和 v4.2
https://linuxize.com/post/how-to-install-and-configure-an-nfs-server-on-centos-8/
```
sudo dnf install nfs-utils
sudo systemctl enable --now nfs-server

sudo mkdir -p /srv/nfs4/{backups,www}

cat > /etc/exports <<EOF
/srv/nfs4         *(rw,sync,no_subtree_check,no_root_squash)
EOF

# https://computingforgeeks.com/install-and-configure-nfs-server-on-centos-rhel/
sudo firewall-cmd --add-service=nfs --permanent
sudo firewall-cmd --add-service={nfs3,mountd,rpc-bind} --permanent 
sudo firewall-cmd --reload

# export nfs share on nfs server
sudo exportfs -r 

# check nfsd versions
sudo cat /proc/fs/nfsd/versions

# mount nfs with version 3
mkdir -p /tmp/nfs
mount -t nfs -o nfsvers=3 10.66.208.121:/srv/nfs4 /tmp/nfs
ls /tmp/nfs
touch /tmp/nfs/aaa
umount /tmp/nfs
```

### 一些关于 Edge 和 IoT 的链接
https://docs.microsoft.com/en-us/answers/questions/611375/installing-iot-edge-on-rhel-8.html<br>
https://mobyproject.org/<br>

### OSP 16.2 关于 virt:av module 的问题
https://bugzilla.redhat.com/show_bug.cgi?id=2027787#c4<br>
https://bugzilla.redhat.com/show_bug.cgi?id=2030377<br>

### Load Balancer 与 Kerberos
http://ssimo.org/blog/id_019.html

### 在 Windows 上配置 Acrylic DNS Proxy 实现通配符域名解析
https://mayakron.altervista.org/support/acrylic/Windows10Configuration.htm<br>
https://stackoverflow.com/questions/138162/wildcards-in-a-windows-hosts-file<br>

### Log4Shell 的缓解方法
https://access.redhat.com/security/cve/CVE-2021-44228<br>
https://access.redhat.com/solutions/6578421<br>
```
CVE-2021-44228

Mitigation
There are two possible mitigations for this flaw in versions from 2.10 to 2.14.1:
- Set the system property log4j2.formatMsgNoLookups to true, or
- Remove the JndiLookup class from the classpath. For example:

zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class

On OpenShift 4 and in OpenShift Logging, the above mitigation can be applied by following this article: https://access.redhat.com/solutions/6578421
```

### WinSCP 与 S3
https://konsole.zendesk.com/hc/en-us/articles/360037885173-How-to-Access-Imports-Exports-on-S3-Using-WinSCP<br>
```
需要注意设置: 
Advanced -> Environment -> S3 -> URL style = Path
```

### Ceph使用系列之——Ceph RGW使用
https://www.codenong.com/cs106856875/

### ceph-dokan MOUNT CEPHFS ON WINDOWS
https://docs.ceph.com/en/latest/cephfs/ceph-dokan/
```
# 参考: https://docs.ceph.com/en/latest/cephfs/ceph-dokan/
# 参考: https://docs.ceph.com/en/latest/install/windows-install/
# 从以下网址下载：https://cloudbase.it/ceph-for-windows/
# Mount a Ceph cluster on Windows 10 using Ceph Dokan
# https://www.youtube.com/watch?v=MAPMO9Z7kbE
# https://cloudbase.it/ceph-on-windows-part-1/

# Windows 配置文件
C:/ProgrameData/ceph/ceph.conf

[global]
    log to stderr = true
    ; Uncomment the following to use Windows Event Log
    ; log to syslog = true
 
    run dir = C:/ProgramData/ceph/out
    crash dir = C:/ProgramData/ceph/out
 
    ; Use the following to change the cephfs client log level
    ; debug client = 2
[client]
    keyring = C:/ProgramData/ceph/keyring
    ; log file = C:/ProgramData/ceph/out/$name.$pid.log
    admin socket = C:/ProgramData/ceph/out/$name.$pid.asok
 
    ; client_permissions = true
    ; client_mount_uid = 1000
    ; client_mount_gid = 1000
[global]
    mon host = 10.66.208.125

# 创建文件 C:/ProgrameData/ceph/keyring
# 为文件添加合适的 keyring 内容
# ceph auth list
# 例如
cat > keyring <<'EOF'
[client.cephfs.1]
   key = AQCG6LZhcpH5GhAA2qal1ZACWGTJgiFsJlhjcw==
EOF
# 目前测试的情况是 client.admin 可以用 ceph-dokan.exe 挂载
# client.cephfs.1 不行

# 到 ceph-dokan.exe 所在的文件夹，挂载 cephfs 文件系统
e:\
cd "Program Files\Ceph\bin"
ceph-dokan.exe -l x

# 报错处理

```

### NetApp 加密
https://www.netapp.com/company/trust-center/security/encryption/
```
Encryption of data in transit - 传输中的数据
Encryption of data at rest - 存储上未使用的数据
Encryption of data in use - 正在使用中的数据
```

### Encrypting NFSv4 with TLS and STunnel
https://www.linuxjournal.com/content/encrypting-nfsv4-stunnel-tls

### radosgw encryption
https://docs.ceph.com/en/latest/radosgw/encryption/

### Ceph CSI encrypted pvc
https://github.com/ceph/ceph-csi/blob/devel/docs/design/proposals/encrypted-pvc.md

### NFS-RGW
https://docs.ceph.com/en/latest/radosgw/nfs/

### stunnel and OpenShift
http://cpitman.github.io/openshift/tcp/networking/2016/12/28/stunnel-and-openshift.html#.Ybfz-L1BxfV

### Ceph Mgr
https://zhuanlan.zhihu.com/p/52139003<br>
https://docs.ceph.com/en/pacific/mgr/index.html<br>
https://docs.ceph.com/en/latest/mgr/administrator/<br>

### ceph 报错信息分析
```
[root@jwang-ceph04 ~]# ceph health detail
HEALTH_WARN 96 pgs not scrubbed in time
[WRN] PG_NOT_SCRUBBED: 96 pgs not scrubbed in time
...
    pg 2.10 not scrubbed since 2021-12-03T07:00:48.798209+0000
    46 more pgs... 

https://tracker.ceph.com/issues/44959
ceph health detail | ag 'not deep-scrubbed since' | awk '{print $2}' | while read pg; do ceph pg deep-scrub $pg; done

ceph health detail | grep -E 'not scrubbed since' | awk '{print $2}' | while read pg; do echo ceph pg scrub $pg; done
ceph health detail | grep -E 'not scrubbed since' | awk '{print $2}' | while read pg; do ceph pg scrub $pg; done

# 测试重启 ceph mgr systemd 服务
systemctl stop ceph-a31452c6-53f2-11ec-a115-001a4a16016f@mgr.jwang-ceph04.example.com.myares.service
systemctl start ceph-a31452c6-53f2-11ec-a115-001a4a16016f@mgr.jwang-ceph04.example.com.myares.service
systemctl status ceph-a31452c6-53f2-11ec-a115-001a4a16016f@mgr.jwang-ceph04.example.com.myares.service

# 通过 orch module 重启 mgr
cephadm shell -- ceph orch restart mgr

# 报错 WARNING: The same type, major and minor should not be used for multiple devices.
# 这个报错是来自 podman 
# https://github.com/opencontainers/runtime-tools/issues/695
# https://tracker.ceph.com/issues/51668
# 参考本文移除 device-mapper 设备部分，可以消除这个告警
[root@jwang-ceph04 ceph]# ls -l /dev/dm*
brw-rw----. 1 root disk 253, 0 Dec  2 09:38 /dev/dm-0
brw-rw----. 1 root disk 253, 1 Dec  2 09:38 /dev/dm-1
brw-rw----. 1 root disk 253, 2 Dec  2 09:38 /dev/dm-2
brw-rw----. 1 root disk 253, 3 Dec  3 14:11 /dev/dm-3
brw-rw----. 1 root disk 253, 4 Dec  3 14:11 /dev/dm-4
brw-rw----. 1 root disk 253, 5 Dec  3 14:13 /dev/dm-5
[root@jwang-ceph04 ceph]# ls -l /dev/mapper/
total 0
brw-rw----. 1 ceph ceph 253,   4 Dec 14 15:11 ceph--20632c65--91ac--4924--849b--f54e392a3999-osd--block--6be9216c--153d--4959--b818--498c1e1f79b4
brw-rw----. 1 ceph ceph 253,   5 Dec 14 15:11 ceph--31c8737c--4ec0--49ea--b26b--e733989461c3-osd--block--fded4dd6--696e--43df--9247--8df0cd161ce5
brw-rw----. 1 ceph ceph 253,   4 Dec  3 08:07 ceph--55676940--281c--43fc--9b71--d359acecb778-osd--block--e0b08b95--d184--4dd8--9748--e495c5225caa
brw-rw----. 1 ceph ceph 253,   3 Dec 14 15:11 ceph--5c2ef1ac--2a33--42e7--bc7c--96aec8a2550b-osd--block--5ece89a4--cabb--4d7a--8b8b--c7baa75a1cb6
brw-rw----. 1 ceph ceph 253,   5 Dec  2 17:25 ceph--9cb74522--f080--4e25--a6fa--3b6b8a893444-osd--block--82b96e58--bb69--4492--a320--993a963890c6
brw-rw----. 1 ceph ceph 253,   3 Dec  2 17:25 ceph--d534c556--1abd--4739--94c8--4c6fa8bfe12c-osd--block--65634030--05cd--4305--b08a--6bd8c43d8c76


# 查看 cephadm shell - ceph-volume lvm list
cephadm shell -- ceph-volume lvm list
# 查看节点磁盘
cephadm shell -- ceph-volume inventory

# 获取 mgr 实例
ceph status 
# 查看 mgr osd_deep_scrub_interval 和 mon_warn_pg_not_deep_scrubbed_ratio 的设置
ceph config show-with-defaults mgr.jwang-ceph04.example.com.myares | egrep "osd_deep_scrub_interval|mon_warn_pg_not_deep_scrubbed_ratio"


```

### F5 SPK and ICNI
Service Proxy for Kubernetes<br>
https://clouddocs.f5.com/service-proxy/latest/spk-sp-deploy-openshift.html<br>
Intelligent CNI 2.0<br>
https://clouddocs.f5.com/service-proxy/latest/spk-sp-deploy-openshift.html<br>
https://clouddocs.f5.com/service-proxy/latest/spk-network-overview.html<br>

### collectd 相关
https://github.com/voxpupuli/puppet-collectd/tree/v12.2.0<br>
https://collectd.org/wiki/index.php/Table_of_Plugins<br>
仔细想想 collectd 并不是适合的日志转发组件

### Ceph and LUA Scripting
https://docs.ceph.com/en/latest/radosgw/lua-scripting/

### 设置 osd-max-backfills 和 osd-recovery-max-active 参数
```
podman exec <CEPH-MON> ceph tell 'osd.*' injectargs --osd-max-backfills=2 --osd-recovery-max-active=6
```

### 测试虚拟机
```
qemu-img create -f qcow2 -o preallocation=metadata /data/kvm/jwang-ocp-bHehlper.qcow2 120G 

# single node 
# 为单节点服务器定义 
# nameserver=192.168.122.1 ip=192.168.122.101::192.168.122.1:255.255.255.0:master-0.ocp4-1.example.com:ens3:none

# SNO 的文档
# https://github.com/cchen666/OpenShift-Labs/blob/main/Installation/Single-Node-Openshift.md
# libvirt 网络所提供的 dhcp 服务还是需要的，因为虚拟机默认通过 dhcp 获取 ip 地址
# 编辑 libvirt 网络
virsh net-edit default
...
  <dns>
    <host ip='192.168.122.101'>
      <hostname>api.ocp4-1.example.com</hostname>
    </host>
  </dns>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <host mac='52:54:00:1c:14:57' name='master-0.ocp4-1.example.com' ip='192.168.122.101'/>
    </dhcp>
  </ip>
  <dnsmasq:options>
    <!-- fix for the 5s timeout on DNS -->
    <!-- see https://www.math.tamu.edu/~comech/tools/linux-slow-dns-lookup/ -->
    <dnsmasq:option value="auth-server=ocp4-1.example.com,"/><!-- yes, there is a trailing coma -->
    <dnsmasq:option value="auth-zone=ocp4-1.example.com"/>
    <!-- Wildcard route -->
    <dnsmasq:option value="host-record=lb.ocp4-1.example.com,192.168.123.5"/>
    <dnsmasq:option value="cname=*.apps.ocp4-1.example.com,lb.ocp4-1.example.com"/>
  </dnsmasq:options>


# https://aboullaite.me/effectively-restarting-kvm-libvirt-network/
# https://fabianlee.org/2018/10/22/kvm-using-dnsmasq-for-libvirt-dns-resolution/

# https://serverfault.com/questions/1068551/wildcard-cname-record-specified-by-libvirts-dnsmasqoptions-namespace-doesnt-wo
# dnsmasq and libvirt
# /var/lib/libvirt/dnsmasq/default.conf
# host-record

host-record=lb.ocp4-1.example.com,192.168.122.101
host-record=api.ocp4-1.example.com,192.168.122.101
host-record=api-int.ocp4-1.example.com,192.168.122.101
host-record=master-0.ocp4-1.example.com,192.168.122.101
address=/ocp4-1.example.com/192.168.122.101
address=/apps.ocp4-1.example.com/192.168.122.101
cname=ocp4-1.example.com,lb.ocp4-1.example.com
cname=*.apps.ocp4-1.example.com,lb.ocp4-1.example.com
auth-zone=ocp4-1.example.com
auth-server=ocp4-1.example.com,*

/usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.conf 


local=/.ocp4-1.example.com/192.168.122.101
local=/.apps.ocp4-1.example.com/192.168.122.101
address=/console-openshift-console.apps.ocp4.terry.com/10.72.44.132
address=/oauth-openshift.apps.ocp4.terry.com/10.72.44.132
address=/bastion.ocp4.terry.com/10.72.44.127
address=/bootstrap.ocp4.terry.com/10.72.44.128
17:04 <yaoli> address=/master1.ocp4.terry.com/10.72.44.129
17:04 <yaoli> address=/master2.ocp4.terry.com/10.72.44.130
17:04 <yaoli> address=/master3.ocp4.terry.com/10.72.44.131
17:04 <yaoli> address=/etcd-0.ocp4.terry.com/10.72.44.129
17:04 <yaoli> address=/etcd-1.ocp4.terry.com/10.72.44.130
17:04 <yaoli> address=/etcd-2.ocp4.terry.com/10.72.44.131
17:04 <yaoli> address=/worker1.ocp4.terry.com/10.72.44.132
17:04 <yaoli> address=/worker2.ocp4.terry.com/10.72.44.133
17:04 <yaoli> address=/api.ocp4.terry.com/10.72.44.127
17:04 <yaoli> address=/api-int.ocp4.terry.com/10.72.44.127


cat > /etc/dnsmasq.conf <<EOF
domain-needed
resolv-file=/etc/resolv.conf.upstream
strict-order
address=/.ocp4-1.example.com/192.168.122.101
address=/.apps.ocp4-1.example.com/192.168.122.101
address=/lb.ocp4-1.example.com/192.168.122.101
address=/console-openshift-console.apps.ocp4-1.example.com/192.168.122.101
address=/oauth-openshift.apps.ocp4-1.example.com/192.168.122.101
address=/master-0.ocp4-1.example.com/192.168.122.101
address=/etcd-0.ocp4-1.example.com/192.168.122.101
address=/api.ocp4-1.example.com/192.168.122.101
address=/api-int.ocp4-1.example.com/192.168.122.101
address=/grafana-openshift-monitoring.apps.ocp4-1.example.com/192.168.122.101
address=/thanos-querier-openshift-monitoring.apps.ocp4-1.example.com/192.168.122.101
address=/prometheus-k8s-openshift-monitoring.apps.ocp4-1.example.com/192.168.122.101
address=/alertmanager-main-openshift-monitoring.apps.ocp4-1.example.com/192.168.122.101
address=/canary-openshift-ingress-canary.apps.ocp4-1.example.com/192.168.122.101
srv-host=_etcd-server-ssl._tcp.ocp4-1.example.com,etcd-0.ocp4-1.example.com,2380

no-hosts
bind-dynamic
EOF

cat > /etc/resolv.conf.upstream <<EOF
search ocp4-1.example.com
nameserver 10.64.63.6
EOF

cat > /etc/resolv.conf <<EOF
search ocp4-1.example.com
nameserver 127.0.0.1
EOF

systemctl restart dnsmasq
dnsmasq -q 
```

### Single Node OpenShift PoC
https://github.com/eranco74/bootstrap-in-place-poc<br>
https://cloud.redhat.com/blog/deploy-openshift-at-the-edge-with-single-node-openshift<br>
https://cloud.redhat.com/blog/using-the-openshift-assisted-installer-service-to-deploy-an-openshift-cluster-on-metal-and-vsphere<br>

### sshuttle for VPN
https://morning.work/page/2019-06/sshuttle.html<br>
https://linux.cn/article-11476-1.html<br>
```
安装 sshuttle
brew install sshuttle

转发
sshuttle --dns -r user@remotehost 192.168.122.0/0
sshuttle --dns -r root@10.66.208.240 192.168.122.12/32 -x 10.0.0.0/8 

openshift 报错
ingress                                    4.9.9     True        False         True       5h14m   The "default" ingress controller reports Degraded=True: DegradedConditions: One or more other status conditions indicate a degraded state: CanaryChecksSucceeding=False (CanaryChecksRepetitiveFailures: Canary route checks for the default ingress controller are failing)

https://issueexplorer.com/issue/openshift/okd/771

# Single Node OpenShift 设置使用静态 IP 地址
# need to set the value of bootstrapInPlace.installationDisk (in install-config.yaml) to use the value --copy-network <install disk>
# https://github.com/openshift/installer/blob/release-4.9/data/data/bootstrap/bootstrap-in-place/files/usr/local/bin/install-to-disk.sh.template#L19
# https://docs.openshift.com/container-platform/4.9/installing/installing_sno/install-sno-installing-sno.html#generating-the-discovery-iso-manually_install-sno-installing-sno-with-the-assisted-installer

# 手工生成使用静态IP地址的 SNO Discovery ISO
# 参考: https://docs.openshift.com/container-platform/4.9/installing/installing_sno/install-sno-installing-sno.html#generating-the-discovery-iso-manually_install-sno-installing-sno-with-the-assisted-installer


tar -xzf ${OCP_PATH}/ocp-installer/openshift-install-linux-${OCP_VER}.tar.gz -C /usr/local/sbin/

export CLUSTER_ID="ocp4-1"
export CLUSTER_PATH=/data/ocp-cluster/${CLUSTER_ID}
export IGN_PATH=${CLUSTER_PATH}/ignition
export SSH_KEY_PATH=${CLUSTER_PATH}/ssh-key
mkdir -p ${IGN_PATH}
mkdir -p ${SSH_KEY_PATH}

# 生成 CoreOS ssh key
ssh-keygen -t rsa -f ${SSH_KEY_PATH}/id_rsa -N '' 


# 生成 install-config.yaml

export PULL_SECRET_STR=$(cat ${PULL_SECRET_FILE}) 
echo ${PULL_SECRET_STR}

cat > ${IGN_PATH}/install-config.yaml <<EOF
apiVersion: v1
baseDomain: example.com
compute:
- name: worker
  replicas: 0
controlPlane:
  name: master
  replicas: 1
metadata:
  name: ${CLUSTER_ID}
networking:
  networkType: OVNKubernetes
  clusterNetworks:
  - cidr: 10.254.0.0/16
    hostPrefix: 24
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
BootstrapInPlace:
  InstallationDisk: --copy-network /dev/vda
pullSecret: '${PULL_SECRET_STR}'
sshKey: |
$( cat ${SSH_KEY_PATH}/id_rsa.pub | sed 's/^/  /g' )
EOF

mkdir -p ${CLUSTER_PATH}/sno
cd ${CLUSTER_PATH}
cp ${IGN_PATH}/install-config.yaml sno
openshift-install --dir=sno create single-node-ignition-config

alias coreos-installer='podman run --privileged --rm \
        -v /dev:/dev -v /run/udev:/run/udev -v $PWD:/data \
        -w /data quay.io/coreos/coreos-installer:release'

cp sno/bootstrap-in-place-for-live-iso.ign iso.ign

cp ${OCP_PATH}/rhcos/rhcos-${RHCOS_VER}-x86_64-live.x86_64.iso rhcos-live.x86_64.iso

coreos-installer iso ignition embed -fi iso.ign rhcos-live.x86_64.iso

# 等待安装完成
openshift-install --dir=sno wait-for install-complete

# 通过调用 Assisted Installer API 生成节点控制平面静态 IP 
# https://github.com/openshift/enhancements/blob/master/enhancements/rhcos/static-networking-enhancements.md
# https://access.redhat.com/solutions/6135171
# 按照这个步骤尝试为 assisted installer 部署的节点设置静态 IP 地址
cat > sno.yaml <<EOF
dns-resolver:
  config:
    server:
    - 192.168.122.1
interfaces:
- ipv4:
    address:
    - ip: 192.168.122.101
      prefix-length: 24
    dhcp: false
    enabled: true
  name: ens3
  state: up
  type: ethernet
routes:
  config:
  - destination: 0.0.0.0/0
    next-hop-address: 192.168.122.1
    next-hop-interface: eth0
    table-id: 254
EOF

ASSISTED_SERVICE_URL=https://api.openshift.com
CLUSTER_ID="07a16d7e-604c-4949-b4a7-901512140825"
NODE_SSH_KEY="..."
request_body=$(mktemp)

jq -n --arg SSH_KEY "$NODE_SSH_KEY" --arg NMSTATE_YAML1 "$(cat sno.yaml)" \
'{
  "ssh_public_key": $SSH_KEY,
  "image_type": "full-iso",
  "static_network_config": [
    {
      "network_yaml": $NMSTATE_YAML1,
      "mac_interface_map": [{"mac_address": "02:00:00:2c:23:a5", "logical_nic_name": "eth0"}, {"mac_address": "02:00:00:68:73:dc", "logical_nic_name": "eth1"}]
    }
  ]
}' >> $request_body

# 单节点 OpenShift 部署时，检查 SNO 的 DNS 可解析
# lb.ocp4-1.example.com
# api.ocp4-1.example.com
# api-int.ocp4-1.example.com
# 其他的域名目前尚不知道是否需要

# 环境里的 libvirt default network 的 dnsmasq 文件内容
# cat /var/lib/libvirt/dnsmasq/default.conf
##WARNING:  THIS IS AN AUTO-GENERATED FILE. CHANGES TO IT ARE LIKELY TO BE
##OVERWRITTEN AND LOST.  Changes to this configuration should be made using:
##    virsh net-edit default
## or other application using the libvirt API.
##
## dnsmasq conf file created by libvirt
strict-order
local=/.ocp4-1.example.com/192.168.122.101
local=/.apps.ocp4-1.example.com/192.168.122.101
pid-file=/var/run/libvirt/network/default.pid
except-interface=lo
bind-dynamic
interface=virbr0
dhcp-range=192.168.122.1,static
dhcp-no-override
dhcp-authoritative
dhcp-hostsfile=/var/lib/libvirt/dnsmasq/default.hostsfile
addn-hosts=/var/lib/libvirt/dnsmasq/default.addnhosts
host-record=lb.ocp4-1.example.com,192.168.122.101
host-record=master-0.ocp4-1.example.com,192.168.122.101
#cname=ocp4-1.example.com,lb.ocp4-1.example.com
#cname=*.apps.ocp4-1.example.com,lb.ocp4-1.example.com
auth-zone=ocp4-1.example.com
auth-server=ocp4-1.example.com,*
# 执行的启动命令是 /usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.conf

# virsh net-dumpxml default 的内容
<network>
  <name>default</name>
  <uuid>4eb93b42-faf0-43aa-913e-8a454d7c0a0d</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:4e:2e:84'/>
  <dns>
    <host ip='192.168.122.101'>
      <hostname>api.ocp4-1.example.com</hostname>
    </host>
  </dns>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <host mac='52:54:00:1c:14:57' name='master-0.ocp4-1.example.com' ip='192.168.122.101'/>
    </dhcp>
  </ip>
</network>

# openshift 4.9 sample operator
# https://docs.openshift.com/container-platform/4.9/openshift_images/configuring-samples-operator.html

# 为虚拟机做一个直接桥接物理网卡网桥的 dnsmasq.conf
# 其中 assisited installer 要求不能设置 ocp4-1.example.com 的通配 dns 解析
# 因此不能设置 address=/.ocp4-1.example.com/10.66.208.241

cat > /etc/dnsmasq.conf <<EOF
domain-needed
resolv-file=/etc/resolv.conf.upstream
strict-order
local=/.ocp4-1.example.com/10.66.208.241
address=/.apps.ocp4-1.example.com/10.66.208.241
address=/lb.ocp4-1.example.com/10.66.208.241
address=/console-openshift-console.apps.ocp4-1.example.com/10.66.208.241
address=/oauth-openshift.apps.ocp4-1.example.com/10.66.208.241
address=/master-0.ocp4-1.example.com/10.66.208.241
address=/etcd-0.ocp4-1.example.com/10.66.208.241
address=/api.ocp4-1.example.com/10.66.208.241
address=/api-int.ocp4-1.example.com/10.66.208.241
address=/grafana-openshift-monitoring.apps.ocp4-1.example.com/10.66.208.241
address=/thanos-querier-openshift-monitoring.apps.ocp4-1.example.com/10.66.208.241
address=/prometheus-k8s-openshift-monitoring.apps.ocp4-1.example.com/10.66.208.241
address=/alertmanager-main-openshift-monitoring.apps.ocp4-1.example.com/10.66.208.241
address=/canary-openshift-ingress-canary.apps.ocp4-1.example.com/10.66.208.241
srv-host=_etcd-server-ssl._tcp.ocp4-1.example.com,etcd-0.ocp4-1.example.com,2380

no-hosts
bind-dynamic
EOF

# 不知道为什么，dnsmasq 突然不工作了
cat > /etc/dnsmasq.conf <<EOF
domain-needed
resolv-file=/etc/resolv.conf.upstream
strict-order
address=/.ocp4-1.example.com/10.66.208.241
address=/.apps.ocp4-1.example.com/10.66.208.241
no-hosts
bind-dynamic
EOF

# brctl show 
bridge name bridge id           STP enabled     interfaces
br0         8000.782bcb199eba   no              em1
                                        vnet1
# ip a s dev br0 
6: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 78:2b:cb:19:9e:ba brd ff:ff:ff:ff:ff:ff
    inet 10.66.208.240/24 brd 10.66.208.255 scope global noprefixroute br0

# virsh dumpxml jwang-ocp452-master0 | grep interface -B5 -A5 
...
    <interface type='bridge'>
      <mac address='52:54:00:1c:14:57'/>
      <source bridge='br0'/>
      <target dev='vnet1'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>


# 创建 bridge 的命令
# 创建 bridge 类型的 conn br0
[root@undercloud #] nmcli con add type bridge con-name br0 ifname br0
# (可选) 根据实际情况设置 bridge.stp，有时可能因为 bridge.stp 设置导致网络通信不正常，⚠️：在 lab 环境不需要执行
[root@undercloud #] nmcli con mod br0 bridge.stp no

# 修改 vlan 类型的 conn ens4 设置 master 为 br0 （参考）
[root@undercloud #] nmcli con mod ens4 connection.master br0 connection.slave-type 'bridge'

[root@undercloud #] nmcli con mod br0 \
    connection.autoconnect 'yes' \
    connection.autoconnect-slaves 'yes' \
    ipv4.method 'manual' \
    ipv4.address '10.25.149.21/24' \
    ipv4.gateway '10.25.149.1' 

cat << EOF > /root/host-bridge.xml
<network>
  <name>br0</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
EOF

virsh net-define /root/host-bridge.xml
virsh net-start br0
virsh net-autostart --network br0
#virsh net-autostart --network default --disable
#virsh net-destroy default

# 报错
[root@base-pvg ocp4-cluster]# oc --kubeconfig /root/jwang/ocp4-cluster/kubeconfig get nodes
Unable to connect to the server: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kube-apiserver-lb-signer")
[root@base-pvg ocp4-cluster]# oc --kubeconfig /root/jwang/ocp4-cluster/kubeconfig login --loglevel=10 
The server uses a certificate signed by an unknown authority.
You can bypass the certificate check, but any data you send to the server could be intercepted by others.
Use insecure connections? (y/n): y

error: couldn't get https://api.ocp4-1.example.com:6443/.well-known/oauth-authorization-server: unexpected response status 404
[root@base-pvg ocp4-cluster]# oc --kubeconfig /root/jwang/ocp4-cluster/kubeconfig login --loglevel=10 

# 报错 
Error starting build: an image stream cannot be used as build output because the integrated container image registry is not configured
# https://access.redhat.com/solutions/3931871

# 测试
PROXY_URL="http://10.66.208.240:3128/"

export http_proxy="$PROXY_URL"
export https_proxy="$PROXY_URL"
export ftp_proxy="$PROXY_URL"
export no_proxy="127.0.0.1,localhost,.rhsacn.org"

# For curl
export HTTP_PROXY="$PROXY_URL"
export HTTPS_PROXY="$PROXY_URL"
export FTP_PROXY="$PROXY_URL"
export NO_PROXY="127.0.0.1,localhost,.rhsacn.org"
```

### OpenShift 4.2环境离线部署Operatorhub
下面这个不是原创，哎...<br>
https://blog.51cto.com/u_15127570/2712896<br>
https://docs.openshift.com/container-platform/4.7/operators/admin/olm-restricted-networks.html<br>
https://access.redhat.com/articles/4740011<br>
https://docs.openshift.com/container-platform/4.7/operators/understanding/olm-rh-catalogs.html#olm-rh-catalogs<br>
https://docs.openshift.com/container-platform/4.7/operators/operator_sdk/osdk-generating-csvs.html#olm-enabling-operator-for-restricted-network_osdk-generating-csvs<br>
https://docs.openshift.com/container-platform/4.7/cli_reference/opm-cli.html#opm-cli<br>
 
```
# 对于纯离线环境，首先需要修改 OperatorHub/cluster 对象，设置 /spec/disableAllDefaultSources 为 true
# Disable the sources for the default catalogs by adding disableAllDefaultSources: true to the OperatorHub object:
oc patch OperatorHub cluster --type json -p '[{"op": "add", "path": "/spec/disableAllDefaultSources", "value": true}]'

# 可选步骤:
# Pruning an index image 
# 修剪 index image
# 如果不想用默认的 source index image，而是只想使用原有的 source index image 的部分 operator
# 可以参考： https://docs.openshift.com/container-platform/4.7/operators/admin/olm-restricted-networks.html#olm-pruning-index-image_olm-restricted-networks
podman login registry.redhat.io
podman login <target_registry>

podman run -p50051:50051 -it registry.redhat.io/redhat/redhat-operator-index:v4.7
grpcurl -plaintext localhost:50051 api.Registry/ListPackages > packages.out
# Inspect the packages.out file and identify which package names from this list you want to keep in your pruned index. For example:
# In the terminal session where you executed the podman run command, press Ctrl and C to stop the container process.

# 以下命令用 source index image - registry.redhat.io/redhat/redhat-operator-index:v4.7 
# 里选择 advanced-cluster-management,jaeger-product,quay-operator 这几个 index content
# 生成修剪后的 local index image
# 修剪后的 local index image 是 <target_registry>:<port>/<namespace>/redhat-operator-index:v4.7
opm index prune -f registry.redhat.io/redhat/redhat-operator-index:v4.7 -p advanced-cluster-management,jaeger-product,quay-operator [-i registry.redhat.io/openshift4/ose-operator-registry:v4.7] -t <target_registry>:<port>/<namespace>/redhat-operator-index:v4.7 

# 将修剪后的 local index image 推送到离线 registry 
podman push <target_registry>:<port>/<namespace>/redhat-operator-index:v4.7

# 根据 index image 
# Mirroring an Operator catalog

# 在 support.example.com 节点上
podman pull --authfile ${PULL_SECRET_FILE} registry.redhat.io/redhat/redhat-operator-index:v${OCP_MAJOR_VER}
podman pull --authfile ${PULL_SECRET_FILE} registry.redhat.io/redhat/certified-operator-index:v${OCP_MAJOR_VER}
podman pull --authfile ${PULL_SECRET_FILE} registry.redhat.io/redhat/community-operator-index:v${OCP_MAJOR_VER}
podman pull --authfile ${PULL_SECRET_FILE} registry.redhat.io/redhat/community-operator-index:v${OCP_MAJOR_VER}

```

### 更新 kubeadmin password
https://blog.andyserver.com/2021/07/rotating-the-openshift-kubeadmin-password/<br>
https://go.dev/play/<br>
```
Actual Password: BeFXW-cCUiE-LEzjW-p8yXz
Hashed Password: $2a$10$PJtmeqhl70nKFA6edvDvmOL675aiVxft33deqx6.P86NGGhl9LA0m
Data to Change in Secret: JDJhJDEwJFBKdG1lcWhsNzBuS0ZBNmVkdkR2bU9MNjc1YWlWeGZ0MzNkZXF4Ni5QODZOR0dobDlMQTBt
Program exited.

SECRET_DATA="JDJhJDEwJFBKdG1lcWhsNzBuS0ZBNmVkdkR2bU9MNjc1YWlWeGZ0MzNkZXF4Ni5QODZOR0dobDlMQTBt"
kubectl patch secret -n kube-system kubeadmin --type json -p '[{"op": "replace", "path": "/data/kubeadmin", "value": "${SECRET_DATA}"}]

# 恢复 system:admin 用户的 kubeconfig 
https://access.redhat.com/solutions/4679661
# bootstrap 虚拟机的 /var/opt/openshift/auth/kubeconfig 是 system:admin 用户的 kubeconfig

# 安装完 ocp4 后更新 ssh key 
https://access.redhat.com/solutions/3868301

# OCP4 如何为 KubeAPIServer 添加 feature-gates
https://access.redhat.com/solutions/5685971
oc edit kubeapiservers.operator.openshift.io cluster

# azure disconnected operator catalog
https://github.com/deewhyweb/azure-disconnected-operator-catalog

# 报错
JundeMacBook-Pro:docs junwang$ oc --loglevel=10 login https://api.cluster-d8x7p.d8x7p.sandbox580.opentlc.com:6443 -u user1 
I1222 15:45:32.302463   96181 request.go:1181] Response Body: {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"configmaps 
\"motd\" is forbidden: User \"system:anonymous\" cannot get resource \"configmaps\" in API group \"\" in the namespace \"openshift\"","reason":"Forbidde
n","details":{"name":"motd","kind":"configmaps"},"code":403}    

oc adm release mirror -a ${PULL_SECRET_FILE} \
     --from=quay.io/openshift-release-dev/ocp-release:${OCP_VER}-x86_64 --to-dir=${OCP_PATH}/operator-image/mirror_${OCP_VER}

# https://www.its404.com/article/lwlfox/110442762

```


### ocp nfs 设置
```
## 存放本集群Registry数据的根目录
export OCP_CLUSTER_ID="ocp4-1"
export CLUSTER_PATH="/data/ocp-cluster/${OCP_CLUSTER_ID}"
export NFS_OCP_REGISTRY_PATH="/data/ocp-cluster/${OCP_CLUSTER_ID}/nfs/ocp-registry"
## 存放本集群用户数据的根目录
export NFS_USER_FILE_PATH="/data/ocp-cluster/${OCP_CLUSTER_ID}/nfs/userfile"
## 运行NFS Server的域名
export DOMAIN="example.com"
export NFS_DOMAIN=nfs.${DOMAIN}
## 在OCP上运行NFS Client的项目
export NFS_CLIENT_NAMESPACE="csi-nfs"
## NFS Client Image
export NFS_CLIENT_PROVISIONER_IMAGE="quay.io/external_storage/nfs-client-provisioner"  
export PROVISIONER_NAME="kubernetes-nfs"
export STORAGECLASS_NAME="sc-csi-nfs"
export OCP_REGISTRY_PVC_NAME="pvc-ocp-registry"
export OCP_REGISTRY_PV_NAME="pv-ocp-registry"


cat << EOF > ${CLUSTER_PATH}/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-nfs-client-provisioner
  namespace: ${NFS_CLIENT_NAMESPACE}
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: cr-nfs-client-provisioner
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "update", "patch"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: crb-nfs-client-provisioner
subjects:
  - kind: ServiceAccount
    name: sa-nfs-client-provisioner
    namespace: ${NFS_CLIENT_NAMESPACE}
roleRef:
  kind: ClusterRole
  name: cr-nfs-client-provisioner
  apiGroup: rbac.authorization.k8s.io
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: r-nfs-client-provisioner
  namespace: ${NFS_CLIENT_NAMESPACE}
rules:
  - apiGroups: [""]
    resources: ["endpoints"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: rb-nfs-client-provisioner
  namespace: ${NFS_CLIENT_NAMESPACE}
subjects:
  - kind: ServiceAccount
    name: sa-nfs-client-provisioner
    namespace: ${NFS_CLIENT_NAMESPACE}
roleRef:
  kind: Role
  name: r-nfs-client-provisioner
  apiGroup: rbac.authorization.k8s.io
EOF

# 8.3.4.2.4	创建deployment.yaml文件
cat << EOF > ${CLUSTER_PATH}/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nfs-client-provisioner
  namespace: ${NFS_CLIENT_NAMESPACE}
  labels:
    app: nfs-client-provisioner
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: nfs-client-provisioner
  template:
    metadata:
      labels:
        app: nfs-client-provisioner
    spec:
      serviceAccountName: sa-nfs-client-provisioner
      containers:
        - name: nfs-client-provisioner
          image: ${NFS_CLIENT_PROVISIONER_IMAGE}:latest
          volumeMounts:
            - name: nfs-client-root
              mountPath: /persistentvolumes
          env:
            - name: PROVISIONER_NAME
              value: ${PROVISIONER_NAME}
            - name: NFS_SERVER
              value: ${NFS_DOMAIN}
            - name: NFS_PATH
              value: ${NFS_USER_FILE_PATH}
      volumes:
        - name: nfs-client-root
          nfs:
            server: ${NFS_DOMAIN}
            path: ${NFS_USER_FILE_PATH}
EOF

# 8.3.4.2.5	创建storageclass.yaml文件
cat << EOF > ${CLUSTER_PATH}/storageclass.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${STORAGECLASS_NAME}
provisioner: ${PROVISIONER_NAME}
parameters:
  archiveOnDelete: "false"
EOF
```

### ironic inspector 检查交换机端口特性
https://docs.openstack.org/python-ironic-inspector-client/wallaby/reference/api/ironic_inspector_client.resource.html
```
(undercloud) [stack@undercloud ~]$ openstack baremetal introspection interface list LAB01PCRENK017
(undercloud) [stack@undercloud ~]$ openstack baremetal introspection interface show LAB01PCRENK017 ens11f0
switch_port_link_aggregation_enabled
switch_port_link_aggregation_id
switch_port_link_aggregation_support
```

### 关于 bash 里的字符串截取，替换，删除，条件赋值
https://www.cnblogs.com/xiaoshiwang/p/12401021.html
```
字符串按位置切片
${var:offset:length}
# offset：从第几个开始切
# length：切多长。可以是负数（从最右面开始切多长，注意负号和冒号之间必须有空格）。

字符串模式
模式：
*：代表0个或多个任意字符。
?：代表0个或1个任意字符。

字符串按模式切片（只能从行首或行尾开始切，不能切中间部分）
${var#pattern} ：功能：自左而右，查找var变量所存储的字符串中，第一次出现的pattern，删除pattern所匹配到的所有字符。 注意：匹配到的必须是从行首开始的，不能匹配中间某段。
${var##pattern} ：贪婪模式，匹配到不能再匹配到位置。
${var%pattern} ：功能：自右而左，查找var变量所存储的字符串中，第一次出现的pattern，删除pattern所匹配到的所有字符。 注意：匹配到的必须是从行尾开始的，不能匹配中间某段。
${var%%pattern} ：贪婪模式，匹配到不能再匹配到位置。

字符串替换
pattern是glob风格的
${var/pattern/substr} ：首次。查找var所表示的字符串中，第一次被pattern所匹配到的字符串，以substr替换之。
${var//pattern/substr} ：全部。查找var所表示的字符串中，所有能被pattern所匹配到的字符串，以substr替换之。
${var/#pattern/substr} ：行首。查找var所表示的字符串中，行首被pattern所匹配到的字符串，以substr替换之。
${var/%pattern/substr} ：行尾。查找var所表示的字符串中，行尾被pattern所匹配到的字符串，以substr替换之。

字符串删除
pattern是glob风格的
${var/pattern} ：删除首次。删除var表示的字符串中第一次被pattern匹配到的字符串。
${var//pattern} ：删除全部。删除var表示的字符串中所有被pattern匹配到的字符串。
${var/#pattern} ：删除行首。删除var表示的字符串中所有以pattern为行首匹配到的字符串。
${var/%pattern} ：删除行尾。删除var所表示的字符串中所有以pattern为行尾所匹配到的字符串。

字符大小写转换
${var^^} ：把var中的所有小写字母转换为大写。
${var,,} ：把var中的所有大写字母转换为小写。

变量赋值
${var:-VALUE}：如果变量var为空或者未设置，则返回VALUE；否则返回变量var的值。注意，变量var本身的值不会被修改。
${var:=VALUE}：如果变量var为空或者未设置，则返回VALUE，并将VALUE赋值给变量var；否则返回变量var的值
${var:+VALUE}：如果变量var为空或者未设置，那么不会返回任何值。否则则返回VALUE的值。注意，变量var本身的值不会被修改。
${var:?ERROR_INFO}：如果变量var为空或者未设置，则返回错误信息ERROR_INFO；否则返回变量var的值。
```

### 关于 bash 的 extglob
https://www.linuxjournal.com/content/bash-extended-globbing

### D 语言
https://dlang.org/

### Harvester HCI
https://harvesterhci.io/<br>
https://www.youtube.com/watch?v=wVBXkS1AgHg<br>

### AI 工具帮助用户
https://www.techradar.com/news/new-ai-tool-eliminates-a-common-nightmare-for-hard-drive-users

### Rancher Longhorn
https://github.com/longhorn/longhorn<br>

### Code Ready Container
https://www.linuxtechi.com/setup-single-node-openshift-cluster-rhel-8/

### Single Node OpenShift
https://www.itix.fr/blog/deploy-openshift-single-node-in-kvm/
```
为单节点 OpenShift 配置使用本地目录的 PV, StorageClass 
# 登陆 SNO 节点
# 创建 /srv/openshift/pv-{0..99} 目录
# 设置目录的访问模式 (777) 和 selinux context (svirt_sanbox_file_t)
ssh core@node.itix-dev.ocp.itix "sudo /bin/bash -c 'mkdir -p /srv/openshift/pv-{0..99} ; chmod -R 777 /srv/openshift ; chcon -R -t svirt_sandbox_file_t /srv/openshift'"

# 创建 PV 
for i in {0..99}; do
  oc create -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-$i
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 10Gi
  accessModes:
  - ReadWriteOnce
  - ReadWriteMany
  persistentVolumeReclaimPolicy: Recycle
  hostPath:
    path: "/srv/openshift/pv-$i"
EOF
done

# 创建 StorageClass
oc create -f - <<EOF
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: manual
  annotations:
    storageclass.kubernetes.io/is-default-class: 'true'
provisioner: kubernetes.io/no-provisioner
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF

# 创建为内部 image-registry 准备的 pvc 
oc create -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: registry-storage
  namespace: openshift-image-registry
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: 10Gi
EOF

# 将 SNO 原来的 configs.imageregistry.operator.openshift.io/cluster 的 /spec/storge 删除
# 然后添加 
# spec:
#   storage:
#     pvc:
#       claim: "registry-storage"
oc patch configs.imageregistry.operator.openshift.io cluster --type=json --patch-file=/dev/fd/0 <<EOF
[{"op": "remove", "path": "/spec/storage" },{"op": "add", "path": "/spec/storage", "value": {"pvc":{"claim": "registry-storage"}}}]
EOF

# 将 configs.imageregistry.operator.openshift.io/cluster 的 spec.managemntState 设置为 Managed
# spec:
#   managementState: "Managed"
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch-file=/dev/fd/0 <<EOF
{"spec":{"managementState": "Managed"}}
EOF

配置 openshift-image-registry 使用
```

### dnsmasq 做 dns 服务器和 dhcp 服务器
https://www.yinxiang.com/everhub/note/89e026c1-c57b-433e-a5d6-78646ec7b6cd

### koji 架构
https://fedoraproject.org/wiki/Koji<br>
https://oepkgs.net/zh/<br>

### OpenShift Automated Release Team tooling
https://github.com/openshift/art-tools

### Yocto and OpenEmbedded
https://www.yoctoproject.org/<br>
https://github.com/openembedded<br>
https://blog.csdn.net/weixin_44410537/article/details/89741876<br>

### osp 启用 vif 的 multiqueue 
```
需要在 flavor 和 image 上设置 properties: vif_multiqueue_enabled
(overcloud) [stack@sne01vrhelu01 ~]$ openstack flavor show m1.dpdk2 -f yaml
[...]
disk: 100
name: m1.dpdk2
properties: hw:cpu_policy='dedicated', hw:cpu_thread_policy='isolate', hw:emulator_threads_policy='share',
  hw:mem_page_size='1GB', hw:vif_multiqueue_enabled='true'
ram: 4096
rxtx_factor: 1.0
vcpus: 2
```

### Why does fstrim fail on Red Hat Enterprise Linux VMs on VMware hypervisors?
https://access.redhat.com/solutions/773263
```
lsblk -s --output NAME,MAJ:MIN,DISC-ALN,DISC-GRAN,DISC-MAX,DISC-ZERO,MOUNTPOINT /dev/rhel/root

cat /sys/block/sdd/device/scsi_disk/3\:0\:0\:2/provisioning_mode 
```

### kickstart file
```
cat > jwang-ocp4-aHelper-ks.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart
network --device=eth0 --hostname=support.example.com --bootproto=static --ip=192.168.122.12 --netmask=255.255.255.0 --gateway=192.168.122.1 --nameserver=192.168.122.1
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal
kexec-tools
tar
%end
EOF

# rhel 7.8
# ks=http://10.66.208.115/jwang-ocp4-aHelper-ks.cfg nameserver=192.168.122.1 ip=192.168.122.12::192.168.122.1:255.255.255.0:support.example.com:eth0:none

```

### 下载 OCP 介质
```
export OCP_MAJOR_VER=4.9
export OCP_VER=4.9.9
export OCP_PATH=/data/OCP-${OCP_VER}/ocp
export YUM_PATH=/data/OCP-${OCP_VER}/yum

mkdir -p ${OCP_PATH}/{app-image,ocp-client,ocp-image,ocp-installer,rhcos,secret}  ${YUM_PATH}

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

export SUB_USER=XXXXX
export SUB_PASSWD=XXXXX

subscription-manager register --force --user ${SUB_USER} --password ${SUB_PASSWD}
subscription-manager refresh
LC_ALL="en_US.UTF-8" LANG="en_US.UTF-8" subscription-manager list --available --matches 'Red Hat OpenShift Container Platform' | grep -E "Pool ID|System Type"

subscription-manager attach --pool=<ONE-POOL-ID>

subscription-manager repos --disable="*"
subscription-manager repos \
    --enable="rhel-7-server-rpms" \
    --enable="rhel-7-server-extras-rpms" \
    --enable="rhel-7-server-ose-${OCP_MAJOR_VER}-rpms" 

yum -y install yum-utils createrepo 
for repo in $(subscription-manager repos --list-enabled | grep "Repo ID" | awk '{print $3}'); do
    reposync --gpgcheck -lmn --repoid=${repo} --download_path=${YUM_PATH}
    createrepo -v ${YUM_PATH}/${repo} -o ${YUM_PATH}/${repo} 
done

du -lh ${YUM_PATH} --max-depth=1

cd ${YUM_PATH}
for dir in $(ls --indicator-style=none ${YUM_PATH}/); do
    tar -zcvf ${YUM_PATH}/${dir}.tar.gz ${dir}; 
done

rm -rf $(ls ${YUM_PATH} |egrep -v gz)
subscription-manager unregister

curl -L https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OCP_VER}/openshift-client-linux-${OCP_VER}.tar.gz -o ${OCP_PATH}/ocp-client/openshift-client-linux-${OCP_VER}.tar.gz
tar -xzf ${OCP_PATH}/ocp-client/openshift-client-linux-${OCP_VER}.tar.gz -C /usr/local/sbin/
oc version

export PULL_SECRET_FILE=${OCP_PATH}/secret/redhat-pull-secret.json

oc adm release info "quay.io/openshift-release-dev/ocp-release:${OCP_VER}-x86_64" 
oc adm release mirror -a ${PULL_SECRET_FILE} \
     --from=quay.io/openshift-release-dev/ocp-release:${OCP_VER}-x86_64 --to-dir=${OCP_PATH}/ocp-image/mirror_${OCP_VER}
oc adm release info ${OCP_VER} --dir=${OCP_PATH}/ocp-image/mirror_${OCP_VER}  
tar -zcvf ${OCP_PATH}/ocp-image/ocp-image-${OCP_VER}.tar -C ${OCP_PATH}/ocp-image ./mirror_${OCP_VER}
rm -rf ${OCP_PATH}/ocp-image/mirror_${OCP_VER}

RHCOS_VER=$(curl -s https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${OCP_MAJOR_VER}/latest/sha256sum.txt | grep x86_64-live.x86_64 | awk -F\- '{print $2}' | head -1)
echo ${RHCOS_VER}

curl -s https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${OCP_MAJOR_VER}/latest/sha256sum.txt | awk '{print $2}' | grep rhcos
curl -L https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${OCP_MAJOR_VER}/${RHCOS_VER}/rhcos-${RHCOS_VER}-x86_64-live.x86_64.iso -o ${OCP_PATH}/rhcos/rhcos-${RHCOS_VER}-x86_64-live.x86_64.iso
ll -h ${OCP_PATH}/rhcos

curl -L https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OCP_VER}/openshift-install-linux-${OCP_VER}.tar.gz -o ${OCP_PATH}/ocp-installer/openshift-install-linux-${OCP_VER}.tar.gz
ll -h ${OCP_PATH}/ocp-installer
tar -xzf ${OCP_PATH}/ocp-installer/openshift-install-linux-${OCP_VER}.tar.gz -C /usr/local/sbin/

上传介质
# 关于参数 --checksum
# https://serverfault.com/questions/211005/rsync-difference-between-checksum-and-ignore-times-options
rsync -r -v  --copy-links --checksum --stats --progress /data/OCP-4.9.9 10.66.208.240:/data

# 看了 rsync 的参数说明后，感觉应该用
rsync -a -v  --copy-links --checksum --stats --progress /data/OCP-4.9.9 10.66.208.240:/data

```


### Single Node OpenShift
https://github.com/eranco74/bootstrap-in-place-poc/blob/main/README.md<br>

### rhel 7 通过 rescue 恢复 root 口令
https://www.thegeekdiary.com/centos-rhel-7-reset-root-password/<br>
https://access.redhat.com/discussions/1243493<br>
```
# Reboot and edit grub2

# Append rd.break to kernel

# Reboot the system
# Press CTLR+x after appending the rd.break to the kernel. This will reboot the system into emergency mode.

# Remount sysroot
mount -o remount,rw /sysroot
chroot /sysroot

# Reset root password
passwd

# SElinux relabeling
touch /.autorelabel

# sync
sync

# Reboot
exit
exit

```

### 参考以下步骤，安装 single node openshift
https://github.com/wangjun1974/tips/blob/master/ocp/offline/4.6/0-prepare.md
```
# 4.6.3	配置Zone区域        
# 4.6.3.1	设置DNS环境变量
setVAR DOMAIN example.com
setVAR OCP_CLUSTER_ID ocp4-1
setVAR BASTION_IP 192.168.122.13
setVAR SUPPORT_IP 192.168.122.12
setVAR DNS_IP 192.168.122.12
setVAR NTP_IP 192.168.122.12
setVAR YUM_IP 192.168.122.12
setVAR NFS_IP 192.168.122.12
setVAR REGISTRY_IP 192.168.122.12
setVAR USIP 192.168.122.12
setVAR LB_IP 192.168.122.12  
setVAR BOOTSTRAP_IP 192.168.122.200
setVAR MASTER0_IP 192.168.122.201

# 4.6.3.2	添加解析Zone区域
# 执行以下命令添加3个解析ZONE（如果要执行多次，需要手动删除以前增加的内容），它们分别为：
# 域名后缀              解释
# example.com          集群内部域名后缀：集群内部所有节点的主机名均采用该域名后缀
# ocp4-1.example.com   OCP集群的域名，如本例中的集群名为ocp4-1，则域名为ocp4-1.example.com
# 168.192.in-addr.arpa 用于集群内所有节点的反向解析
cat >> /etc/named.rfc1912.zones << EOF

zone "${DOMAIN}" IN {
        type master;
        file "${DOMAIN}.zone";
        allow-transfer { any; };
};

zone "${OCP_CLUSTER_ID}.${DOMAIN}" IN {
        type master;
        file "${OCP_CLUSTER_ID}.${DOMAIN}.zone";
        allow-transfer { any; };
};

zone "168.192.in-addr.arpa" IN {
        type master;
        file "168.192.in-addr.arpa.zone";
        allow-transfer { any; };
};

EOF

# 4.6.3.3	创建example.com.zone区域配置文件
cat > /var/named/${DOMAIN}.zone << EOF
\$ORIGIN ${DOMAIN}.
\$TTL 1D
@           IN SOA  ${DOMAIN}. admin.${DOMAIN}. (
                                        0          ; serial
                                        1D         ; refresh
                                        1H         ; retry
                                        1W         ; expire
                                        3H )       ; minimum

@             IN NS                         dns.${DOMAIN}.

bastion       IN A                          ${BASTION_IP}
support       IN A                          ${SUPPORT_IP}
dns           IN A                          ${DNS_IP}
ntp           IN A                          ${NTP_IP}
yum           IN A                          ${YUM_IP}
registry      IN A                          ${REGISTRY_IP}
nfs           IN A                          ${NFS_IP}

EOF

# 4.6.3.4	创建ocp4-1.example.com.zone区域配置文件
cat > /var/named/${OCP_CLUSTER_ID}.${DOMAIN}.zone << EOF
\$ORIGIN ${OCP_CLUSTER_ID}.${DOMAIN}.
\$TTL 1D
@           IN SOA  ${OCP_CLUSTER_ID}.${DOMAIN}. admin.${OCP_CLUSTER_ID}.${DOMAIN}. (
                                        0          ; serial
                                        1D         ; refresh
                                        1H         ; retry
                                        1W         ; expire
                                        3H )       ; minimum

@             IN NS                         dns.${DOMAIN}.

lb             IN A                          ${LB_IP}

api            IN A                          ${LB_IP}
api-int        IN A                          ${LB_IP}
*.apps         IN A                          ${LB_IP}

bootstrap      IN A                          ${BOOTSTRAP_IP}

master-0       IN A                          ${MASTER0_IP}

etcd-0         IN A                          ${MASTER0_IP}

_etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN}. 8640 IN SRV 0 10 2380 etcd-0.${OCP_CLUSTER_ID}.${DOMAIN}.

EOF

# 4.6.3.5	创建168.192.in-addr.arpa.zone反向解析区域配置文件
# 注意：以下脚本中的反向IP如果有变化需要在此手动修改。
cat > /var/named/168.192.in-addr.arpa.zone << EOF
\$TTL 1D
@           IN SOA  ${DOMAIN}. admin.${DOMAIN}. (
                                        0       ; serial
                                        1D      ; refresh
                                        1H      ; retry
                                        1W      ; expire
                                        3H )    ; minimum
                                        
@                              IN NS       dns.${DOMAIN}.

13.122.168.192.in-addr.arpa.     IN PTR      bastion.${DOMAIN}.

12.122.168.192.in-addr.arpa.     IN PTR      support.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      dns.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      ntp.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      yum.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      registry.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      nfs.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      lb.${OCP_CLUSTER_ID}.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      api.${OCP_CLUSTER_ID}.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      api-int.${OCP_CLUSTER_ID}.${DOMAIN}.

200.122.168.192.in-addr.arpa.    IN PTR      bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}.

201.122.168.192.in-addr.arpa.    IN PTR      master-0.${OCP_CLUSTER_ID}.${DOMAIN}.
EOF

# 4.6.4	重启BIND服务
# 重启BIND服务，然后检查没有错误日志。
systemctl restart named
rndc reload
journalctl -u named

# 4.6.5	将Support节点的DNS配置指向自己
nmcli c mod "$(nmcli --fields name con show |awk 'NR==2{print}' | sed -e 's, $,,g')" ipv4.dns "${DNS_IP}"
systemctl restart network
nmcli c show "$(nmcli --fields name con show |awk 'NR==2{print}' | sed -e 's, $,,g')" | grep ipv4.dns

# 4.6.6	测试正反向DNS解析
# 1.	正向解析测试
dig nfs.${DOMAIN} +short
dig support.${DOMAIN} +short 
dig yum.${DOMAIN} +short
dig registry.${DOMAIN} +short
dig ntp.${DOMAIN} +short
dig lb.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig api.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig api-int.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig *.apps.${OCP_CLUSTER_ID}.${DOMAIN} +short

dig bastion.${DOMAIN} +short

dig bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} +short

dig master-0.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig etcd-0.${OCP_CLUSTER_ID}.${DOMAIN} +short

dig _etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN} SRV +short

# 2.	反向解析测试
dig -x ${BASTION_IP} +short
dig -x ${SUPPORT_IP} +short
dig -x ${BOOTSTRAP_IP} +short
dig -x ${MASTER0_IP} +short

# 4.7	配置远程正式YUM源
# 4.7.1	配置Support节点的YUM源
# 1.	删除临时yum源
mv /etc/yum.repos.d/base.repo{,.bak}
# 2.	创建yum repo配置文件
setVAR YUM_DOMAIN yum.${DOMAIN}:8080
cat > /etc/yum.repos.d/ocp.repo << EOF
[rhel-7-server]
name=rhel-7-server
baseurl=http://${YUM_DOMAIN}/repo/rhel-7-server-rpms/
enabled=1
gpgcheck=0

[rhel-7-server-extras] 
name=rhel-7-server-extras
baseurl=http://${YUM_DOMAIN}/repo/rhel-7-server-extras-rpms/
enabled=1
gpgcheck=0

[rhel-7-server-ose] 
name=rhel-7-server-ose
baseurl=http://${YUM_DOMAIN}/repo/rhel-7-server-ose-${OCP_MAJOR_VER}-rpms/
enabled=1
gpgcheck=0 

EOF
yum repolist

# 4.7.2	安装基础软件包，验证YUM源
# 在Support节点安装以下软件包，验证YUM源是正常的。
yum -y install wget git net-tools bridge-utils jq tree httpd-tools 

# 4.8	部署NTP服务
# 注意：下文将Support节点当做OpenShift集群的NTP服务源。如果用户已经有NTP服务，可以忽略此节，并在安装OpenShift集群后将集群节点的时间服务指向已有的NTP服务。
# 4.8.1	设置正确的时区
timedatectl set-timezone Asia/Shanghai
timedatectl status | grep 'Time zone'
# 4.8.2	配置chrony服务
# 1.	RHEL 7.8最小化安装会安装chrony时间服务软件。我们先查看chrony服务状态：
systemctl status chronyd
yum install chrony
2.	备份原始chrony.conf配置文件，再修改配置文件
cp /etc/chrony.conf{,.bak}
sed -i -e "s/^server*/#&/g" \
       -e "s/#local stratum 10/local stratum 10/g" \
       -e "s/#allow 192.168.0.0\/16/allow all/g" \
       /etc/chrony.conf
cat >> /etc/chrony.conf << EOF
server ntp.${DOMAIN} iburst
EOF
# 3.	重启chrony服务
systemctl enable --now chronyd
systemctl restart chronyd
# 4.8.3	检查chrony服务端启动
ps -auxw |grep chrony
ss -lnup |grep chronyd
systemctl status chronyd
chronyc -n sources -v

# 4.9	部署本地Docker Registry
# 该Docker Registry镜像库用于提供OCP安装过程所需的容器镜像。
# 4.9.1	创建Docker Registry相关目录
## 容器镜像库存放的根目录
setVAR REGISTRY_PATH /data/registry
mkdir -p ${REGISTRY_PATH}/{auth,certs,data}

# 文档里的方法
openssl req -newkey rsa:4096 -nodes -sha256 -keyout ${REGISTRY_PATH}/certs/registry.key -x509 -days 3650 \
  -out ${REGISTRY_PATH}/certs/registry.crt \
  -subj "/C=CN/ST=BEIJING/L=BJ/O=REDHAT/OU=IT/CN=registry.${DOMAIN}/emailAddress=admin@${DOMAIN}"
openssl x509 -in ${REGISTRY_PATH}/certs/registry.crt -text | head -n 14

# 4.9.3	安装Docker Registry
# 1.	安装docker-distribution
yum -y install docker-distribution

# 2.	创建Registry认证凭据，允许用openshift/redhat登录。
htpasswd -bBc ${REGISTRY_PATH}/auth/htpasswd openshift redhat
cat ${REGISTRY_PATH}/auth/htpasswd

# 3.	创建docker-distribution配置文件
setVAR REGISTRY_DOMAIN registry.${DOMAIN}:5000                  ## 容器镜像库的访问域名

cat << EOF > /etc/docker-distribution/registry/config.yml
version: 0.1
log:
  fields:
    service: registry
storage:
    cache:
        layerinfo: inmemory
    filesystem:
        rootdirectory: ${REGISTRY_PATH}/data
    delete:
        enabled: false
auth:
  htpasswd:
    realm: basic-realm
    path: ${REGISTRY_PATH}/auth/htpasswd
http:
    addr: 0.0.0.0:5000
    host: https://${REGISTRY_DOMAIN}
    tls:
      certificate: ${REGISTRY_PATH}/certs/registry.crt
      key: ${REGISTRY_PATH}/certs/registry.key
EOF
cat /etc/docker-distribution/registry/config.yml

# 4.	启动Registry镜像库服务
systemctl enable docker-distribution --now
systemctl status docker-distribution

# 4.9.4	从本地访问Docker Registry 
# 将访问Registry的证书复制到RHEL系统的默认目录，然后更新到系统中。
cp ${REGISTRY_PATH}/certs/registry.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust
curl -u openshift:redhat https://${REGISTRY_DOMAIN}/v2/_catalog

# 4.9.6	导入OpenShift核心镜像到Docker Registry
# 4.9.6.1	设置基础环境变量
setVAR REGISTRY_REPO ocp4/openshift4       ## 在Docker Registry中存放OpenShift核心镜像的Repository
setVAR GODEBUG x509ignoreCN=0

# 4.9.6.2	安装镜像操作工具并登录Docker Registry
yum -y install podman skopeo 
# 用openshift/redhat登录Docker Registry，并将生成的免密登录信息追加到${PULL_SECRET_FILE文件。
setVAR PULL_SECRET_FILE ${OCP_PATH}/secret/redhat-pull-secret.json
cp ${OCP_PATH}/secret/redhat-pull-secret.json{,.bak}
podman login -u openshift -p redhat --authfile ${PULL_SECRET_FILE} ${REGISTRY_DOMAIN}
cat $PULL_SECRET_FILE | jq -c | tee $PULL_SECRET_FILE

# 4.9.6.3	向Docker Registry导入OpenShift核心镜像
tar -xvf ${OCP_PATH}/ocp-image/ocp-image-${OCP_VER}.tar -C ${OCP_PATH}/ocp-image/
rm -f ${OCP_PATH}/ocp-image/ocp-image-${OCP_VER}.tar

oc image mirror -a ${PULL_SECRET_FILE} \
     --dir=${OCP_PATH}/ocp-image/mirror_${OCP_VER} "file://openshift/release:${OCP_VER}*" ${REGISTRY_DOMAIN}/${REGISTRY_REPO}

# 查看已经导入镜像库镜像数量，然后查看镜像信息。
curl -u openshift:redhat https://${REGISTRY_DOMAIN}/v2/_catalog
curl -u openshift:redhat -s https://${REGISTRY_DOMAIN}/v2/${REGISTRY_REPO}/tags/list |jq -M '.["tags"][]' | wc -l
curl -u openshift:redhat -s https://${REGISTRY_DOMAIN}/v2/${REGISTRY_REPO}/tags/list |jq -M '.["name"] + ":" + .["tags"][]' 
oc adm release info -a ${PULL_SECRET_FILE} "${REGISTRY_DOMAIN}/${REGISTRY_REPO}:${OCP_VER}-x86_64" | grep -A 200 -i "Images" 

# 4.10	部署HAProxy负载均衡服务
# 1.	安装Haproxy
yum -y install haproxy
systemctl enable haproxy --now

# 2.	添加haproxy.cfg配置文件
cat <<EOF > /etc/haproxy/haproxy.cfg

# Global settings
#---------------------------------------------------------------------
global
    maxconn     20000
    log         /dev/log local0 info
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
#    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          300s
    timeout server          300s
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 20000

listen stats
    bind :9000
    mode http
    stats enable
    stats uri /

frontend  openshift-api-server-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:6443
    mode tcp
    option tcplog
    default_backend openshift-api-server-${OCP_CLUSTER_ID}

frontend  machine-config-server-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:22623
    mode tcp
    option tcplog
    default_backend machine-config-server-${OCP_CLUSTER_ID}

frontend  ingress-http-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:80
    mode tcp
    option tcplog
    default_backend ingress-http-${OCP_CLUSTER_ID}

frontend  ingress-https-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:443
    mode tcp
    option tcplog
    default_backend ingress-https-${OCP_CLUSTER_ID}

backend openshift-api-server-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     bootstrap bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check

backend machine-config-server-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     bootstrap bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check

backend ingress-http-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:80 check

backend ingress-https-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:443 check
EOF
cat /etc/haproxy/haproxy.cfg

# 3.	重启HAProxy服务, 然后检查HAProxy服务
systemctl restart haproxy
ss -lntp |grep haproxy

# 5	准备定制安装文件
# 5.1	准备Ignition引导文件
# 5.1.1	安装openshift-install
tar -xzf ${OCP_PATH}/ocp-installer/openshift-install-linux-${OCP_VER}.tar.gz -C /usr/local/sbin/
openshift-install version

# 5.1.2	准备install-config.yaml文件
# 5.1.2.1	设置环境变量
setVAR OCP_CLUSTER_ID "ocp4-1"
setVAR REPLICA_WORKER 0                                             ## 在安装阶段，将WORKER的数量设为0
setVAR REPLICA_MASTER 1                                             ## 本文档的OpenShift集群只有1个master节点
setVAR CLUSTER_PATH /data/ocp-cluster/${OCP_CLUSTER_ID}
setVAR IGN_PATH ${CLUSTER_PATH}/ignition                            ## 存放Ignition相关文件的目录

# 将文件调整为 1 行
cat ${PULL_SECRET_FILE} | jq -c | tee ${PULL_SECRET_FILE}
setVAR PULL_SECRET_STR "\$(cat \${PULL_SECRET_FILE})"               ## 在安装过程使用${PULL_SECRET_FILE}拉取镜像
setVAR SSH_KEY_PATH ${CLUSTER_PATH}/ssh-key                         ## 存放ssh-key相关文件的目录
setVAR SSH_PRI_FILE ${SSH_KEY_PATH}/id_rsa                          ## 节点之间访问的私钥文件名

# 5.1.2.2	创建CoreOS SSH访问密钥
# 该密钥用于登录OpenShift集群节点的CoreOS。
mkdir -p ${IGN_PATH}
mkdir -p ${SSH_KEY_PATH}
ssh-keygen -N '' -f ${SSH_KEY_PATH}/id_rsa
ll ${SSH_KEY_PATH}
setVAR SSH_PUB_STR "\$(cat ${SSH_KEY_PATH}/id_rsa.pub)"             ## 节点之间访问的公钥文件内容
echo ${SSH_PUB_STR}

# 5.1.2.3	创建无证书的install-config.yaml文件
cat << EOF > ${IGN_PATH}/install-config.yaml
apiVersion: v1
baseDomain: ${DOMAIN}
compute:
- hyperthreading: Enabled
  name: worker
  replicas: ${REPLICA_WORKER}
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: ${REPLICA_MASTER}
metadata:
  name: ${OCP_CLUSTER_ID}
networking:
  clusterNetworks:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
fips: false
pullSecret: '${PULL_SECRET_STR}'
sshKey: '${SSH_PUB_STR}'
imageContentSources: 
- mirrors:
  - ${REGISTRY_DOMAIN}/${REGISTRY_REPO}
  source: quay.io/openshift-release-dev/ocp-release
- mirrors:
  - ${REGISTRY_DOMAIN}/${REGISTRY_REPO}
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
EOF

# 5.1.2.4	附加Docker Registry镜像库的证书到install-config.yaml文件
cp ${REGISTRY_PATH}/certs/registry.crt ${IGN_PATH}/
sed -i -e 's/^/  /' ${IGN_PATH}/registry.crt
echo "additionalTrustBundle: |" >> ${IGN_PATH}/install-config.yaml
cat ${IGN_PATH}/registry.crt >> ${IGN_PATH}/install-config.yaml

# 5.1.2.5	查看最终的install-config.yaml文件
# 重要说明：由于install-config.yaml中的安装证书有效期只有24小时，因此如果在生成该文件后24小时没有安装好OpenShift集群，需要重新操作生成install-config.yaml和其他所有安装前的准备步骤（所有以前生成的文件可以删除掉）。
cat ${IGN_PATH}/install-config.yaml

# 5.1.2.6	备份install-config.yaml文件
cp ${IGN_PATH}/install-config.yaml{,.`date +%Y%m%d%H%M`.bak}
ll ${IGN_PATH}

# 5.1.3	准备manifest文件
# 5.1.3.1	生成manifest文件
# OpenShift集群节点在启动后会根据manifest文件生成的Ignition设置各自的操作系统配置。
openshift-install create manifests --dir ${IGN_PATH}
tree ${IGN_PATH}/manifests/ ${IGN_PATH}/openshift/

# 5.1.3.2	修改master节点的调度策略
# 单节点集群无需修改
# 修改mastersSchedulable为false, 禁用master节点运行用户负载。
sed -i 's/mastersSchedulable: true/mastersSchedulable: false/g' ${IGN_PATH}/manifests/cluster-scheduler-02-config.yml
cat ${IGN_PATH}/manifests/cluster-scheduler-02-config.yml | grep mastersSchedulable

# 5.1.3.3	为所有节点创建时钟同步配置文件
setVAR NTP_CONF $(cat << EOF | base64 -w 0
server ntp.${DOMAIN} iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF)

echo ${NTP_CONF} | base64 -d

# 创建master节点的创建时钟同步配置文件。
cat << EOF > ${IGN_PATH}/openshift/99_masters-chrony-configuration.yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: master
  name: masters-chrony-configuration
spec:
  config:
    ignition:
      config: {}
      security:
        tls: {}
      timeouts: {}
      version: 3.1.0
    networkd: {}
    passwd: {}
    storage:
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,${NTP_CONF}
        mode: 420
        overwrite: true
        path: /etc/chrony.conf
  osImageURL: ""
EOF
cat ${IGN_PATH}/openshift/99_masters-chrony-configuration.yaml

# 创建worker节点的创建时钟同步配置文件。
# 单节点集群无需执行
cat << EOF > ${IGN_PATH}/openshift/99_workers-chrony-configuration.yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: workers-chrony-configuration
spec:
  config:
    ignition:
      config: {}
      security:
        tls: {}
      timeouts: {}
      version: 3.1.0
    networkd: {}
    passwd: {}
    storage:
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,${NTP_CONF}
        mode: 420
        overwrite: true
        path: /etc/chrony.conf
  osImageURL: ""
EOF
more ${IGN_PATH}/openshift/99_workers-chrony-configuration.yaml

# 5.1.4	创建Ignition引导文件
openshift-install create ignition-configs --dir ${IGN_PATH}/
ll ${IGN_PATH}/*.ign
jq .ignition.config ${IGN_PATH}/master.ign 
jq .ignition.config ${IGN_PATH}/worker.ign 

# 5.2	准备节点自动设置文件
# 为了方面CoreOS节点首次启动后的设置操作，所有操作都放在节点自动设置文件中，只需下载该文件执行即可完成对应节点的所有配置。
setVAR GATEWAY_IP 192.168.122.1      ## CoreOS启动时使用的GATEWAY
setVAR NETMASK 24                  ## CoreOS启动时使用的NETMASK
setVAR CONNECT_NAME "Wired connection 1"    
# CoreOS的nmcli看到的connection名称，OCP4.6 是“Wired Connection”
# CoreOS的nmcli看到的connection名称，OCP4.8 是“Wired connection 1”
# CoreOS的nmcli看到的connection名称，OCP4.9 是“Wired connection 1”
# CoreOS的nmcli看到的connection名称，OCP4.9 如果启动时输入 ip= 参数是 "ens3"

creat_auto_config_file(){

cat << EOF > ${IGN_PATH}/set-${NODE_NAME}
nmcli connection modify "${CONNECT_NAME}" ipv4.addresses ${IP}/${NETMASK}
nmcli connection modify "${CONNECT_NAME}" ipv4.dns ${DNS_IP}
nmcli connection modify "${CONNECT_NAME}" ipv4.gateway ${GATEWAY_IP}
nmcli connection modify "${CONNECT_NAME}" ipv4.method manual
nmcli connection down "${CONNECT_NAME}"
nmcli connection up "${CONNECT_NAME}"

sudo coreos-installer install /dev/sda --insecure-ignition --ignition-url=http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/${NODE_TYPE}.ign --firstboot-args 'rd.neednet=1' --copy-network
EOF
}

#创建BOOTSTRAP启动定制文件
NODE_TYPE="bootstrap"
NODE_NAME="bootstrap"
IP=${BOOTSTRAP_IP}
creat_auto_config_file
cat ${IGN_PATH}/set-${NODE_NAME}

#创建master-0启动定制文件
NODE_TYPE="master"
NODE_NAME="master-0"
IP=${MASTER0_IP}
creat_auto_config_file

#创建master-1启动定制文件
NODE_TYPE="master"
NODE_NAME="master-1"
IP=${MASTER1_IP}
creat_auto_config_file

#创建master-2启动定制文件
NODE_TYPE="master"
NODE_NAME="master-2"
IP=${MASTER2_IP}
creat_auto_config_file

#创建worker-0启动定制文件
NODE_TYPE="worker"
NODE_NAME="worker-0"
IP=${WORKER0_IP}
creat_auto_config_file

#创建worker-1启动定制文件
NODE_TYPE="worker"
NODE_NAME="worker-1"
IP=${WORKER1_IP}
creat_auto_config_file

ll ${IGN_PATH}/set-*

# 5.3	创建文件下载目录
# 为定制文件创建Apache HTTP上的可下载目录。
chmod -R 705 ${IGN_PATH}/
cat << EOF > /etc/httpd/conf.d/ignition.conf
Alias /${OCP_CLUSTER_ID} "${IGN_PATH}/../"
<Directory "${IGN_PATH}/../">
  Options +Indexes +FollowSymLinks
  Require all granted
</Directory>
<Location /${OCP_CLUSTER_ID}>
  SetHandler None
</Location>
EOF
systemctl restart httpd

# 确认所有安装所需文件可下载。
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/bootstrap.ign | jq 
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/worker.ign | jq
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/master.ign | jq
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/set-bootstrap
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/set-master-0
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/set-master-1
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/set-master-2
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/set-worker-0
curl http://${YUM_DOMAIN}/${OCP_CLUSTER_ID}/ignition/set-worker-1

# 6	创建Bootstrap、Master、Worker虚拟机节点
# 具体根据不同的IaaS环境和虚机节点配置要求创建bootstrap、master-0、master-1、master-2、worker-0、worker-1虚拟机节点，方法和过程略。需要注意以下事项：
# 1.	将硬盘的启动优先级设为最高，并将rhcos-4.9.0-x86_64-live.x86_64.iso作为所有虚机的启动盘。
# 2.	为虚拟机配置一个网卡，并使用网桥类型的网络。
# 3.	虚拟机操作系统类型选择RHEL 7或RHEL 8。

# 配置 ip 地址
sudo nmcli con mod 'Wired Connection 1' connection.autoconnect 'yes' ipv4.method 'manual' ipv4.address '192.168.122.200/24' ipv4.gateway '192.168.122.1' ipv4.dns '192.168.122.12'
sudo nmcli con down 'Wired Connection 1'
sudo nmcli con up 'Wired Connection 1'

# 使用命令检查网卡配置是否成功
ip a

# 在bootstrap节点中执行以下命令，先下载自动配置文件，然后执行它。注意：由于此节点当前还未完成配置，因此只能通过IP地址获取自动配置文件。
curl -O http://<SOPPORT-IP>:8080/<OCP_CLUSTER_ID>/ignition/set-bootstrap
source set-bootstrap
# 执行命令重启bootstrap节点。
reboot


# 7.1.2	查看bootstrap节点部署进程
# 1.	删除以前ssh保留的登录主机信息。
rm -rf ~/.ssh/known_hosts
# 2.	检查bootstrap节点的镜像库mirror配置是否按照install-config.yaml的内容进行配置
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "sudo cat /etc/containers/registries.conf"
# 3.	检查bootstrap节点是否能访问到Registry。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "curl -s -u openshift:redhat https://registry.${DOMAIN}:5000/v2/_catalog"
# 4.	检查bootstrap节点的本地pods。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "sudo crictl pods"
# 5.	访问如下地址http://lb.ocp4-1.example.internal:9000/，确认只有两处bootstrap节点变为绿色。
# 6.	确认可以通过curl命令查看machine config配置服务是否启动。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "curl -kIs https://api-int.${OCP_CLUSTER_ID}.${DOMAIN}:22623/config/master"

# 7.	可通过如下命令从宏观面观察部署过程。
openshift-install wait-for install-complete --log-level=debug --dir=${IGN_PATH}

# 8.	跟踪bootstrap的日志以识别安装进度，当循环出现如下红色字体提示的内容的时候，并且haproxy的web监控界面openshift-api-server和machine-config-server的bootstrap部分变为绿色时，说明bootstrap的引导服务已经启动，此时可进入下一个阶段。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "journalctl -b -f -u bootkube.service"

# 7.2	第二阶段：部署master阶段
# 7.2.1	两次启动
# 参照bootstrap的两次启动步骤启动所有master节点，将网络参数换成各自master的地址。
# 7.2.2	查看master节点部署进程
# 在support节点执行命令检查master节点的镜像库配置是否按照install-config.yaml的内容进行配置
ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "sudo cat /etc/containers/registries.conf"
# 检查是否能够正常访问registry
ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "curl -s -u openshift:redhat https://registry.${DOMAIN}:5000/v2/_catalog"
# 安装过程中可以通过查看如下日志来跟踪安装过程。注意以下日志的红色字体部分，这些内容指示master的不同安装阶段
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "journalctl -b -f -u bootkube.service"
# 出现上述最后两条红色字体后，说明bootstrap的任务已经完成，可以已经进入后续安装部署节点
# 另外，我们也可以通过如下方法了解安装进程：
tail -f ${IGN_PATH}/.openshift_install.log 
openshift-install wait-for bootstrap-complete --log-level debug --dir ${IGN_PATH}
# 现在我们可以关闭bootstrap节点，继续进行下一个阶段部署。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "sudo shutdown -h now"
# 在安装过程中，也可以通过以下方法查看master节点的日志 
# ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "journalctl -xef"

# 复制kubeconfig文件到用户缺省目录，以便可以用oc命令访问集群。
mkdir ~/.kube
cp ${IGN_PATH}/auth/kubeconfig ~/.kube/config

# 检查节点状态，确保master的STATUS均为Ready状态
oc get node

# 7.3	第三阶段：部署worker阶段
# 单节点集群不执行
# 7.3.1	两次启动
# 参照bootstrap的两次启动步骤启动所有worker节点，将网络参数换成各自worker的地址。
# 等待 worker machine-config-daemon-firstboot service 完成
ssh -i ${SSH_PRI_FILE} core@worker-1.${OCP_CLUSTER_ID}.${DOMAIN} "sudo journalctl -f -u machine-config-daemon-firstboot.service"

# 7.3.2	批准csr请求
# 通过如下命令查看 csr批准请求，第一批出现的是“kube-apiserver-client-kubelet”相关csr。
oc get csr | grep Pending
# 执行以下命令批准请求。
oc get csr | grep Pending | awk '{print $1}' | xargs oc adm certificate approve
# 再次执行命令查看 csr批准请求，第二批出现的是“kubelet-serving”相关csr。
oc get csr | grep Pending
# 执行以下命令批准请求。
oc get csr | grep Pending | awk '{print $1}' | xargs oc adm certificate approve

# 7.3.3	查看集群部署进展
# 执行以下命令来查看集群部署是否完成，整个过程需要一些时间。出现以下红色字体部分，说明集群已经部署完成。请记下kubeadmin和对应的登录密码。
oc get node
oc get clusteroperators
oc get clusterversion
tail -f ${IGN_PATH}/.openshift_install.log
openshift-install wait-for install-complete --log-level debug --dir ${IGN_PATH}

# 检查 kube-apiserver operator 日志
oc -n openshift-kube-apiserver-operator logs $(oc get pods -n openshift-kube-apiserver-operator -o jsonpath='{ .items[*].metadata.name }') -f

# 在单节点安装时，bootstrap 完成后
# 按照这个链接里的内容，进行了针对 single node 环境的 patch
# 目前尚不确认这些 patch 是否有必要
# https://docs.google.com/document/d/1bYSwibEPfg-hq1DW7Qn2En6maswiN9C8f85aW5uYgUw/edit
# 1. 设置 etcd-operator 支持在少于 3 个 master 节点的情况下启动 etcd cluster 
# Etcd patch - allow etcd-operator to start the etcd cluster without minimum of 3 master nodes
oc --kubeconfig ${IGN_PATH}/auth/kubeconfig patch etcd cluster -p='{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}' --type=merge

# 2. 设置 cluster-authentication-operator 在少于 3 个 master 节点的情况下部署 OAuthServer 
# Authentication patch -  allow cluster-authentication-operator to deploy OAuthServer without minimum of 3 master nodes
oc --kubeconfig ${IGN_PATH}/auth/kubeconfig patch authentications.operator.openshift.io cluster -p='{"spec": {"managementState": "Managed", "unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableOAuthServer": true}}}' --type=merge

# 3. 设置 1 个 ingress router pod
# 4.9.9 上无需执行
# Make sure to have a single ingress router pod:
oc patch --kubeconfig ${IGN_PATH}/auth/kubeconfig -n openshift-ingress-operator ingresscontroller/default --patch '{"spec":{"replicas": 1}}' --type=merge

# 4. 标记 openshift-etcd namespace 下的 etcd-quorum-guard deployment 为 unmanaged: true
# 4.9.9 上没有这个 deployment
oc --kubeconfig ${IGN_PATH}/auth/kubeconfig patch clusterversion/version --type='merge' -p "$(cat <<- EOF
 spec:
    overrides:
      - group: apps/v1
        kind: Deployment
        name: etcd-quorum-guard
        namespace: openshift-etcd
        unmanaged: true
EOF
)"

# 5. 这个命令在 4.9.9 上无需执行
# 4.9.9 上没有这个 deployment
oc --kubeconfig ${IGN_PATH}/auth/kubeconfig scale --replicas=1 deployment/etcd-quorum-guard -n openshift-etcd

# 6. 查看安装进度 clusterversion
oc --kubeconfig ${IGN_PATH}/auth/kubeconfig get clusterversion

[root@support ~]# oc --kubeconfig=/data/ocp-cluster/ocp4-1/get nodes
ignition/ ssh-key/  
[root@support ~]# oc --kubeconfig=/data/ocp-cluster/ocp4-1/ignition/auth/kubeconfig get clusterversion 
NAME      VERSION   AVAILABLE   PROGRESSING   SINCE   STATUS
version   4.9.9     True        False         3m33s   Cluster version is 4.9.9

[root@support ~]# oc --kubeconfig=/data/ocp-cluster/ocp4-1/ignition/auth/kubeconfig get clusteroperators 
NAME                                       VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE   MESSAGE
authentication                             4.9.9     True        False         False      6m9s    
baremetal                                  4.9.9     True        False         False      11m     
cloud-controller-manager                   4.9.9     True        False         False      18m     
cloud-credential                           4.9.9     True        False         False      67m     
cluster-autoscaler                         4.9.9     True        False         False      13m     
config-operator                            4.9.9     True        False         False      16m     
console                                    4.9.9     True        False         False      5m51s   
csi-snapshot-controller                    4.9.9     True        False         False      15m     
dns                                        4.9.9     True        False         False      11m     
etcd                                       4.9.9     True        False         False      13m     
image-registry                             4.9.9     True        False         False      10m     
ingress                                    4.9.9     True        False         False      9m13s   
insights                                   4.9.9     True        False         False      4m24s   
kube-apiserver                             4.9.9     True        False         False      10m     
kube-controller-manager                    4.9.9     True        False         False      13m     
kube-scheduler                             4.9.9     True        False         False      14m     
kube-storage-version-migrator              4.9.9     True        False         False      16m     
machine-api                                4.9.9     True        False         False      14m     
machine-approver                           4.9.9     True        False         False      14m     
machine-config                             4.9.9     True        False         False      14m     
marketplace                                4.9.9     True        False         False      14m     
monitoring                                 4.9.9     True        False         False      6m12s   
network                                    4.9.9     True        False         False      16m     
node-tuning                                4.9.9     True        False         False      14m     
openshift-apiserver                        4.9.9     True        False         False      6m42s   
openshift-controller-manager               4.9.9     True        False         False      9m9s    
openshift-samples                          4.9.9     True        False         False      10m     
operator-lifecycle-manager                 4.9.9     True        False         False      14m     
operator-lifecycle-manager-catalog         4.9.9     True        False         False      15m     
operator-lifecycle-manager-packageserver   4.9.9     True        False         False      12m     
service-ca                                 4.9.9     True        False         False      16m     
storage                                    4.9.9     True        False         False      16m     

[root@support ~]# oc --kubeconfig=/data/ocp-cluster/ocp4-1/ignition/auth/kubeconfig get node
NAME                          STATUS   ROLES           AGE   VERSION
master-0.ocp4-1.example.com   Ready    master,worker   22m   v1.22.3+4dd1b5a

# 参考以下链接里的步骤，设置 SNO 的存储
# https://www.itix.fr/blog/deploy-openshift-single-node-in-kvm/
# 登陆 SNO 节点
# 创建 /srv/openshift/pv-{0..99} 目录
# 设置目录的访问模式 (777) 和 selinux context (svirt_sanbox_file_t)
ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN}  "sudo /bin/bash -c 'mkdir -p /srv/openshift/pv-{0..99} ; chmod -R 777 /srv/openshift ; chcon -R -t svirt_sandbox_file_t /srv/openshift'"

# 创建 PV 
for i in {0..99}; do
  oc create -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-$i
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 10Gi
  accessModes:
  - ReadWriteOnce
  - ReadWriteMany
  persistentVolumeReclaimPolicy: Recycle
  hostPath:
    path: "/srv/openshift/pv-$i"
EOF
done

# 创建 StorageClass
oc create -f - <<EOF
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: manual
  annotations:
    storageclass.kubernetes.io/is-default-class: 'true'
provisioner: kubernetes.io/no-provisioner
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF

# 创建为内部 image-registry 准备的 pvc 
oc create -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: registry-storage
  namespace: openshift-image-registry
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: 10Gi
EOF

# 将 SNO 原来的 configs.imageregistry.operator.openshift.io/cluster 的 /spec/storge 删除
# 然后添加 
# spec:
#   storage:
#     pvc:
#       claim: "registry-storage"
oc patch configs.imageregistry.operator.openshift.io cluster --type=json --patch-file=/dev/fd/0 <<EOF
[{"op": "remove", "path": "/spec/storage" },{"op": "add", "path": "/spec/storage", "value": {"pvc":{"claim": "registry-storage"}}}]
EOF

# 将 configs.imageregistry.operator.openshift.io/cluster 的 spec.managemntState 设置为 Managed
# spec:
#   managementState: "Managed"
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch-file=/dev/fd/0 <<EOF
{"spec":{"managementState": "Managed"}}
EOF

# 根据 https://github.com/eranco74/bootstrap-in-place-poc/blob/main/README.md
# 测试 SNO LiveCD 方法
git clone https://github.com/eranco74/bootstrap-in-place-poc
cd bootstrap-in-place-poc
mkdir sno-workdir

# 生成 install-config.yaml
# BootstrapInPlace - InstallationDisk
# https://github.com/openshift/installer/blob/release-4.9/data/data/bootstrap/bootstrap-in-place/files/usr/local/bin/install-to-disk.sh.template#L19
cat << EOF > sno-workdir/install-config.yaml
apiVersion: v1
baseDomain: ${DOMAIN}
compute:
- hyperthreading: Enabled
  name: worker
  replicas: ${REPLICA_WORKER}
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: ${REPLICA_MASTER}
metadata:
  name: ${OCP_CLUSTER_ID}
networking:
  clusterNetworks:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
BootstrapInPlace:
  InstallationDisk: --copy-network /dev/vda  
fips: false
pullSecret: '${PULL_SECRET_STR}'
sshKey: '${SSH_PUB_STR}'
imageContentSources: 
- mirrors:
  - ${REGISTRY_DOMAIN}/${REGISTRY_REPO}
  source: quay.io/openshift-release-dev/ocp-release
- mirrors:
  - ${REGISTRY_DOMAIN}/${REGISTRY_REPO}
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
EOF

# 5.1.2.4	附加Docker Registry镜像库的证书到install-config.yaml文件
cp ${REGISTRY_PATH}/certs/registry.crt sno-workdir/
sed -i -e 's/^/  /' sno-workdir/registry.crt
echo "additionalTrustBundle: |" >> sno-workdir/install-config.yaml
cat sno-workdir/registry.crt >> sno-workdir/install-config.yaml

# 拷贝 base.iso
cp /data/OCP-4.9.9/ocp/rhcos/rhcos-4.9.0-x86_64-live.x86_64.iso sno-workdir/base.iso

# 准备 openshift-install 
# 之前已经解压缩过了

# 生成 Manifests
INSTALLATION_DISK=/dev/vda \
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.9.9-x86_64 \
INSTALLER_BIN=/usr/local/sbin/openshift-install \
INSTALLER_WORKDIR=./sno-workdir \
./manifests.sh
cp ./manifests/*.yaml $INSTALLER_WORKDIR/manifests/

# 生成 Single-Node-Ignition-Config ignition 
INSTALLATION_DISK=/dev/vda \
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.9.9-x86_64 \
INSTALLER_BIN=/usr/local/sbin/openshift-install \
INSTALLER_WORKDIR=./sno-workdir \
./generate.sh

# 生成 sno embeded livecd iso
ISO_PATH=./sno-workdir/base.iso \
IGNITION_PATH=./sno-workdir/bootstrap-in-place-for-live-iso.ign \
OUTPUT_PATH=./sno-workdir/embedded.iso \
./embed.sh

# 调整 dns 
# 4.6.3.4	创建ocp4-1.example.com.zone区域配置文件
cat > /var/named/${OCP_CLUSTER_ID}.${DOMAIN}.zone << EOF
\$ORIGIN ${OCP_CLUSTER_ID}.${DOMAIN}.
\$TTL 1D
@           IN SOA  ${OCP_CLUSTER_ID}.${DOMAIN}. admin.${OCP_CLUSTER_ID}.${DOMAIN}. (
                                        0          ; serial
                                        1D         ; refresh
                                        1H         ; retry
                                        1W         ; expire
                                        3H )       ; minimum

@             IN NS                         dns.${DOMAIN}.

lb             IN A                          ${LB_IP}

api            IN A                          ${LB_IP}
api-int        IN A                          ${LB_IP}
*.apps         IN A                          ${LB_IP}

bootstrap      IN A                          ${MASTER0_IP}

master-0       IN A                          ${MASTER0_IP}

etcd-0         IN A                          ${MASTER0_IP}

_etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN}. 8640 IN SRV 0 10 2380 etcd-0.${OCP_CLUSTER_ID}.${DOMAIN}.

EOF

# 4.6.3.5	创建168.192.in-addr.arpa.zone反向解析区域配置文件
# 注意：以下脚本中的反向IP如果有变化需要在此手动修改。
cat > /var/named/168.192.in-addr.arpa.zone << EOF
\$TTL 1D
@           IN SOA  ${DOMAIN}. admin.${DOMAIN}. (
                                        0       ; serial
                                        1D      ; refresh
                                        1H      ; retry
                                        1W      ; expire
                                        3H )    ; minimum
                                        
@                              IN NS       dns.${DOMAIN}.

13.122.168.192.in-addr.arpa.     IN PTR      bastion.${DOMAIN}.

12.122.168.192.in-addr.arpa.     IN PTR      support.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      dns.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      ntp.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      yum.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      registry.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      nfs.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      lb.${OCP_CLUSTER_ID}.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      api.${OCP_CLUSTER_ID}.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      api-int.${OCP_CLUSTER_ID}.${DOMAIN}.

201.122.168.192.in-addr.arpa.    IN PTR      bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}.

201.122.168.192.in-addr.arpa.    IN PTR      master-0.${OCP_CLUSTER_ID}.${DOMAIN}.
EOF

# 4.6.4	重启BIND服务
# 重启BIND服务，然后检查没有错误日志。
systemctl restart named
rndc reload
journalctl -u named

# 2.	添加haproxy.cfg配置文件
cat <<EOF > /etc/haproxy/haproxy.cfg

# Global settings
#---------------------------------------------------------------------
global
    maxconn     20000
    log         /dev/log local0 info
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
#    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          300s
    timeout server          300s
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 20000

listen stats
    bind :9000
    mode http
    stats enable
    stats uri /

frontend  openshift-api-server-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:6443
    mode tcp
    option tcplog
    default_backend openshift-api-server-${OCP_CLUSTER_ID}

frontend  machine-config-server-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:22623
    mode tcp
    option tcplog
    default_backend machine-config-server-${OCP_CLUSTER_ID}

frontend  ingress-http-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:80
    mode tcp
    option tcplog
    default_backend ingress-http-${OCP_CLUSTER_ID}

frontend  ingress-https-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:443
    mode tcp
    option tcplog
    default_backend ingress-https-${OCP_CLUSTER_ID}

backend openshift-api-server-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check

backend machine-config-server-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check

backend ingress-http-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:80 check

backend ingress-https-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:443 check
EOF
cat /etc/haproxy/haproxy.cfg

# 3.	重启HAProxy服务, 然后检查HAProxy服务
systemctl restart haproxy
ss -lntp |grep haproxy

# 6	创建 SNO 虚拟机节点
# 具体根据不同的IaaS环境和虚机节点配置要求创建 master-0 虚拟机节点，方法和过程略。需要注意以下事项：
# 1.	将硬盘的启动优先级设为最高，并将 embedded.iso 作为虚机的启动盘。
# 2.	为虚拟机配置一个网卡，并使用网桥类型的网络。
# 3.	虚拟机操作系统类型选择RHEL 7或RHEL 8。
# 启动参数添加 nameserver=192.168.122.12 ip=192.168.122.201::192.168.122.1:255.255.255.0:master-0.ocp4-1.example.com:ens3:none

# 7.1.2	查看bootstrap节点部署进程
# 1.	删除以前ssh保留的登录主机信息。
rm -rf ~/.ssh/known_hosts
# 2.	检查bootstrap节点的镜像库mirror配置是否按照install-config.yaml的内容进行配置
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "sudo cat /etc/containers/registries.conf"
# 3.	检查bootstrap节点是否能访问到Registry。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "curl -s -u openshift:redhat https://registry.${DOMAIN}:5000/v2/_catalog"
# 4.	检查bootstrap节点的本地pods。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "sudo crictl pods"
# 5.	访问如下地址http://lb.ocp4-1.example.internal:9000/，确认只有两处bootstrap节点变为绿色。
# 6.	确认可以通过curl命令查看machine config配置服务是否启动。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "curl -kIs https://api-int.${OCP_CLUSTER_ID}.${DOMAIN}:22623/config/master"

# 7.	可通过如下命令从宏观面观察部署过程。
openshift-install wait-for install-complete --log-level=debug --dir=${IGN_PATH}

# 8.	跟踪bootstrap的日志以识别安装进度，当循环出现如下红色字体提示的内容的时候，并且haproxy的web监控界面openshift-api-server和machine-config-server的bootstrap部分变为绿色时，说明bootstrap的引导服务已经启动，此时可进入下一个阶段。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "journalctl -b -f -u bootkube.service"

# 7.2	第二阶段：部署master阶段
# 7.2.1	两次启动
# 参照bootstrap的两次启动步骤启动所有master节点，将网络参数换成各自master的地址。
# 7.2.2	查看master节点部署进程
# 在support节点执行命令检查master节点的镜像库配置是否按照install-config.yaml的内容进行配置
ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "sudo cat /etc/containers/registries.conf"
# 检查是否能够正常访问registry
ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "curl -s -u openshift:redhat https://registry.${DOMAIN}:5000/v2/_catalog"
# 安装过程中可以通过查看如下日志来跟踪安装过程。注意以下日志的红色字体部分，这些内容指示master的不同安装阶段
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "journalctl -b -f -u bootkube.service"
# 出现上述最后两条红色字体后，说明bootstrap的任务已经完成，可以已经进入后续安装部署节点
# 另外，我们也可以通过如下方法了解安装进程：
tail -f ${IGN_PATH}/.openshift_install.log 
openshift-install wait-for bootstrap-complete --log-level debug --dir ${IGN_PATH}
# 现在我们可以关闭bootstrap节点，继续进行下一个阶段部署。
ssh -i ${SSH_PRI_FILE} core@bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} "sudo shutdown -h now"
# 在安装过程中，也可以通过以下方法查看master节点的日志 
# ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "journalctl -xef"

```


### 报错
```
oc image mirror -a ${PULL_SECRET_FILE} --from-dir=${OCP_PATH}/ocp-image/mirror_${OCP_VER} "file://openshift/release:${OCP_VER}-x86_64*" ${REGISTRY_DOMAIN}/${REGISTRY_REPO} --loglevel=8
I1227 21:07:46.203600    3054 config.go:128] looking for config.json at /root/.docker/config.json
I1227 21:07:46.203840    3054 config.go:94] looking for .dockercfg at /root/.dockercfg
I1227 21:07:46.204818    3054 file.go:30] Repository https://registry-1.docker.io openshift/release
I1227 21:07:46.206264    3054 options.go:59] Search for "4.9.9*" (^4\.9\.9.*.*$) found: []
F1227 21:07:46.206452    3054 helpers.go:116] error: you must specify at least one source image to pull and the destination to push to as SRC=DST or SRC
 DST [DST2 DST3 ...]

oc adm release info 4.9.9 --dir=/data/OCP-4.9.9/ocp/ocp-image/mirror_4.9.9 | tee /tmp/oc-adm-release-info-4.9.9
oc adm release info 4.6.52 --dir=/data/OCP-4.6.52/ocp/ocp-image/mirror_4.6.52 | tee /tmp/oc-adm-release-info-4.6.52

# 怀疑是运行命令时 soft link 信息丢失了
#  rsync -r -v --stats --progress <srcdir> <dsthost>:<dstdir>
# 重新创建 soft link
oc adm release info 4.9.9 --dir=/data/OCP-4.9.9/ocp/ocp-image/mirror_4.9.9 |  grep sha256 | grep -Ev "Digest|Pull" | while read name digest ; do ln -sf $digest 4.9.9-x86_64-${name} ;  done  
oc adm release info 4.9.9 --dir=/data/OCP-4.9.9/ocp/ocp-image/mirror_4.9.9 |  grep sha256 | grep -E "Digest" | while read name digest ; do ln -sf $digest 4.9.9-x86_64 ;  done

[root@support ~]# ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "sudo crictl logs 12ca25c026f51"
I1228 06:01:25.974215       1 cmd.go:209] Using service-serving-cert provided certificates
I1228 06:01:25.984675       1 observer_polling.go:159] Starting file observer
W1228 06:01:31.388600       1 builder.go:220] unable to get owner reference (falling back to namespace): Get "https://172.30.0.1:443/api/v1/namespaces/o
penshift-kube-apiserver-operator/pods/kube-apiserver-operator-6b6548968f-wswls": dial tcp 172.30.0.1:443: connect: connection refused
I1228 06:01:31.406830       1 builder.go:252] kube-apiserver-operator version 4.9.0-202111151318.p0.g3a02848.assembly.stream-3a02848-3a02848339e2e10e452
2031c1deaec9a6d553063
F1228 06:02:41.111808       1 cmd.go:138] unable to load configmap based request-header-client-ca-file: the server was unable to return a response in the time allotted, but may still be processing the request (get configmaps extension-apiserver-authentication)

[root@support ~]# ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "sudo crictl ps -a | grep apiserver"

[root@support ocp-image]# openssl s_client -showcerts -verify 5 -connect api-int.ocp4-1.example.com:6443 < /dev/null 

[root@support ~]# ssh -i ${SSH_PRI_FILE} core@master-0.${OCP_CLUSTER_ID}.${DOMAIN} "sudo crictl logs e9e10fa4eb18f 2>&1 | head -20 " 
I1228 06:15:56.019683       1 cmd.go:209] Using service-serving-cert provided certificates
I1228 06:15:56.020236       1 observer_polling.go:74] Adding reactor for file "/var/run/secrets/serving-cert/tls.crt"
I1228 06:15:56.021123       1 observer_polling.go:74] Adding reactor for file "/var/run/secrets/serving-cert/tls.key"
I1228 06:15:56.021304       1 observer_polling.go:52] Starting from specified content for file "/var/run/configmaps/config/operator-config.yaml"
I1228 06:15:56.022353       1 observer_polling.go:159] Starting file observer
I1228 06:15:56.023317       1 observer_polling.go:135] File observer successfully synced
W1228 06:15:56.032629       1 builder.go:220] unable to get owner reference (falling back to namespace): Get "https://172.30.0.1:443/api/v1/namespaces/openshift-service-ca-operator/pods": dial tcp 172.30.0.1:443: connect: connection refused
I1228 06:15:56.032902       1 builder.go:252] service-ca-operator version v4.9.0-202111151318.p0.gab44f58.assembly.stream-0-gb8f3dc1-
I1228 06:15:56.034658       1 dynamic_serving_content.go:110] "Loaded a new cert/key pair" name="serving-cert::/var/run/secrets/serving-cert/tls.crt::/var/run/secrets/serving-cert/tls.key"
I1228 06:15:57.878571       1 server.go:50] Error initializing delegating authentication (will retry): <nil>
# https://bugzilla.redhat.com/show_bug.cgi?id=1933269

```

### ACM 相关
https://cloud.redhat.com/blog/using-the-openshift-assisted-installer-service-to-deploy-an-openshift-cluster-on-metal-and-vsphere<br>
https://github.com/openshift/assisted-service/blob/master/docs/user-guide/restful-api-guide.md#setting-static-network-config<br>
```
# 执行导入命令，
# 创建了
# open-cluster-management crd
# open-cluster-management-agent namespace
# klusterlet serviceaccount
# klusterlet clusterrole
# open-cluster-management:klusterlet-admin-aggregate-clusterrole clusterrole
# klusterlet clusterrolebinding
# bootstrap-hub-kubeconfig secret
# klusterlet deployment
# klusterlet klusterlet
customresourcedefinition.apiextensions.k8s.io/klusterlets.operator.open-cluster-management.io created
namespace/open-cluster-management-agent created
serviceaccount/klusterlet created
secret/bootstrap-hub-kubeconfig created
clusterrole.rbac.authorization.k8s.io/klusterlet created
clusterrole.rbac.authorization.k8s.io/open-cluster-management:klusterlet-admin-aggregate-clusterrole created
clusterrolebinding.rbac.authorization.k8s.io/klusterlet created
deployment.apps/klusterlet created
klusterlet.operator.open-cluster-management.io/klusterlet created
```

### Disk Image Builder 创建 whole disk image 
```
# Disk Image Builder 可以创建 partition image，也可以创建 whole disk image

# Disk Image Builder 创建 whole disk image 的命令
# 命令里的 vm 参数告诉 disk-image-builder 创建 whole disk image
# ToDo: 仔细看看 disk-image-builder 相关资料
# disk-image-create rhel grub2 vm block-dev-efi -o rhel-wholedisk
```

### 镜像仓库
Docker本地镜像发布到阿里云镜像仓库以及拉取操作<br>
http://www.lzhpo.com/article/35<br>

### 暴露 mqtt 服务
```
以下命令生成一个 NodePort Service，这个 Service 可以通过 Node:Port 访问 
oc expose service tb-mqtt-transport --type=NodePort --name=tb-mqtt-transport-ingress --generator="service/v2"
```

### openshift toolbox pod 的使用 
```
$ oc debug node/ip-10-0-159-84.us-east-2.compute.internal 
Starting pod/ip-10-0-159-84us-east-2computeinternal-debug ...
To use host binaries, run `chroot /host`
Pod IP: 10.0.159.84
If you don't see a command prompt, try p
sh-4.4# chroot /host
sh-4.4# toolbox
```
### 配置 NodePort 类型的服务
```
# 暴露 Node Port 类型的服务
oc expose service tb-mqtt-transport --type=NodePort --name=tb-route-mqtt-transport --generator="service/v2"
```

### 配置 LoadBalancer Type 的服务
https://docs.openshift.com/container-platform/4.6/networking/configuring_ingress_cluster_traffic/configuring-ingress-cluster-traffic-load-balancer.html
```
创建 Type 为 LoadBalancer 的 Service
cat << EOF
apiVersion: v1
kind: Service
metadata:
  name: tb-mqtt-ingress-lb 
spec:
  ports:
  - name: mqtt
    port: 1883 
  loadBalancerIP:
  type: LoadBalancer 
  selector:
    app: tb-mqtt-transport
EOF | oc apply -f -

yum install nmap-ncat -y

echo -en "\x10\x0d\x00\x04MQTT\x04\x00\x00\x00\x00\x01a" | nc -v a72bc4fdef91d467ba706a541fdc925f-1741428165.us-east-2.elb.amaznaws.com 1883

echo -en "\x10\x0d\x00\x04MQTT\x04\x00\x00\x00\x00\x01a" | nc -v 72.52.10.14 1883

$ nc -v a72bc4fdef91d467ba706a541fdc925f-1741428165.us-east-2.elb.amazonaws.com 1883
Connection to a72bc4fdef91d467ba706a541fdc925f-1741428165.us-east-2.elb.amazonaws.com port 1883 [tcp/ibm-mqisdp] succeeded!
```

### 镜像服务器
https://hub.daocloud.io/

### OpenShift 上运行 MQTT 服务
https://bigredstack.com/run-mosquitto-mqtt-broker-on-red-hat-openshift/<br>
https://github.com/thingsboard/thingsboard/issues/3637<br>

### 创建 debug node 指定特定的镜像作为 toolbox 镜像
https://access.redhat.com/solutions/4929021
```
$ oc debug node/ip-10-0-159-84.us-east-2.compute.internal --image=quay.io/fedora/fedora:33-x86_64
sh-4.4# chroot /host
sh-4.4# toolbox
# 安装 sysstat 软件包，其中包含 iostat 命令
[root@ip-xx-xx-xx-xx /]# yum install -y sysstat
[root@ip-xx-xx-xx-xx /]# iostat 1 1
```

### 创建带有 group 信息的 repodata
```
# support 机器创建带有 group 信息的 repodata
[root@support rhel-7-server-rpms]# pwd
/data/OCP-4.9.9/yum/rhel-7-server-rpms
[root@support rhel-7-server-rpms]# time createrepo -g $(ls $(pwd)/comps.xml) $(pwd)
[root@support rhel-7-server-rpms]# yum clean all
[root@support rhel-7-server-rpms]# yum grouplist
```

### 安装 openshift ai 虚拟机
```
# 生成 ks.cfg - ocp-ai
cat > ks-ocp-ai.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart
network --device=ens3 --hostname=ocpai.example.com --bootproto=static --ip=192.168.122.14 --netmask=255.255.255.0 --gateway=192.168.122.1 --nameserver=192.168.122.12
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
openssl-perl
%end
EOF

virt-install --debug --name=jwang-ocp-ai --vcpus=4 --ram=32768 --disk path=/data/kvm/jwang-ocp-ai.qcow2,bus=virtio,size=100 --os-variant rhel8.0 --network network=default,model=virtio --boot menu=on --location /root/jwang/isos/rhel-8.4-x86_64-dvd.iso --initrd-inject /tmp/ks-ocp-ai.cfg --extra-args='ks=file:/ks-ocp-ai.cfg'
```

### 离线 OCP OLM 同步脚本
https://github.com/jparrill/ztp-the-hard-way/blob/main/docs/prerequirements/mirror-olm.md
```
#!/bin/bash -e
# Disconnected Operator Catalog Mirror and Minor Upgrade
# Variables to set, suit to your installation

export OCP_RELEASE=4.9
export OCP_RELEASE_FULL=$OCP_RELEASE.9
export ARCHITECTURE=x86_64
export SIGNATURE_BASE64_FILE="signature-sha256-$OCP_RELEASE_FULL.yaml"
export OCP_PULLSECRET_AUTHFILE='/root/pull_secret.json'
export LOCAL_REGISTRY=registry.example.com:5000
export LOCAL_REGISTRY_MIRROR_TAG=/ocp4/openshift4
export LOCAL_REGISTRY_INDEX_TAG=olm-index/redhat-operator-index:v$OCP_RELEASE
export LOCAL_REGISTRY_INDEX_TAG_COMM=olm-index/community-operator-index:v$OCP_RELEASE
export LOCAL_REGISTRY_IMAGE_TAG=olm

# Set these values to true for the catalog and miror to be created
export RH_OP='true'
export CERT_OP='false'
export COMM_OP='true'
export MARKETPLACE_OP='false'

export RH_OP_INDEX="registry.redhat.io/redhat/redhat-operator-index:v${OCP_RELEASE}"
export CERT_OP_INDEX="registry.redhat.io/redhat/certified-operator-index:v${OCP_RELEASE}"
export COMM_OP_INDEX="registry.redhat.io/redhat/community-operator-index:v${OCP_RELEASE}"
export MARKETPLACE_OP_INDEX="registry.redhat.io/redhat-marketplace-index:v${OCP_RELEASE}"
export RH_OP_PACKAGES='advanced-cluster-management,cluster-logging,kubevirt-hyperconverged,local-storage-operator,ocs-operator,performance-addon-operator,ptp-operator,sriov-network-operator'
#export RH_OP_PACKAGES='advanced-cluster-management,local-storage-operator,ocs-operator,performance-addon-operator,ptp-operator,sriov-network-operator'
export COMM_OP_PACKAGES='hive-operator'

if [ $# -lt 1 ]
then
        echo "Usage : $0 mirror|mirror-olm|upgrade"
        exit
fi

mirror () {
# Mirror redhat-operator index image

if [ "${RH_OP}" = true ]
  then
    echo "opm index prune --from-index $RH_OP_INDEX --packages $RH_OP_PACKAGES --tag $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG"
    opm index prune --from-index $RH_OP_INDEX --packages $RH_OP_PACKAGES --tag $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG
    GODEBUG=x509ignoreCN=0 podman push --tls-verify=false $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG --authfile $OCP_PULLSECRET_AUTHFILE
    GODEBUG=x509ignoreCN=0 oc adm catalog mirror $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG $LOCAL_REGISTRY/$LOCAL_REGISTRY_IMAGE_TAG --registry-config=$OCP_PULLSECRET_AUTHFILE

    cat > redhat-operator-index-manifests/catalogsource.yaml << EOF
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: my-operator-catalog
  namespace: openshift-marketplace
spec:
  sourceType: grpc
  image: $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG
  displayName: Temp Lab
  publisher: templab
  updateStrategy:
    registryPoll:
      interval: 30m
EOF

    echo ""
    echo "To apply the Red Hat Operators catalog mirror configuration to your cluster, do the following once per cluster:"
    echo "oc apply -f ./redhat-operator-index-manifests/imageContentSourcePolicy.yaml"
    echo "oc apply -f ./redhat-operator-index-manifests/catalogsource.yaml"
fi

if [ "${CERT_OP}" = true ]
  then
    "echo 1"
fi

if [ "${COMM_OP}" = true ]
  then
    echo "opm index prune --from-index $COMM_OP_INDEX --packages $COMM_OP_PACKAGES --tag $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG_COMM"
    opm index prune --from-index $COMM_OP_INDEX --packages $COMM_OP_PACKAGES --tag $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG_COMM
    GODEBUG=x509ignoreCN=0 podman push --tls-verify=false $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG_COMM --authfile $OCP_PULLSECRET_AUTHFILE
    GODEBUG=x509ignoreCN=0 oc adm catalog mirror $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG_COMM $LOCAL_REGISTRY/$LOCAL_REGISTRY_IMAGE_TAG --registry-config=$OCP_PULLSECRET_AUTHFILE

    cat > community-operator-index-manifests/catalogsource.yaml << EOF
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: my-community-operator-catalog
  namespace: openshift-marketplace
spec:
  sourceType: grpc
  image: $LOCAL_REGISTRY/$LOCAL_REGISTRY_INDEX_TAG_COMM
  displayName: Temp Lab
  publisher: templab
  updateStrategy:
    registryPoll:
      interval: 30m
EOF

    echo ""
    echo "To apply the Red Hat Operators catalog mirror configuration to your cluster, do the following once per cluster:"
    echo "oc apply -f ./community-operator-index-manifests/imageContentSourcePolicy.yaml"
    echo "oc apply -f ./community-operator-index-manifests/catalogsource.yaml"

fi

if [ "${MARKETPLACE_OP}" = true ]
  then
    "echo 3"
fi

}

mirror-olm () {
# hack for broken operators

for packagemanifest in $(oc get packagemanifest -n openshift-marketplace -o name) ; do
  for package in $(oc get $packagemanifest -o jsonpath='{.status.channels[*].currentCSVDesc.relatedImages}' | sed "s/ /\n/g" | tr -d '[],' | sed 's/"/ /g') ; do
    echo
    echo "Package: ${package}"
    skopeo copy docker://$package docker://$LOCAL_REGISTRY/$LOCAL_REGISTRY_IMAGE_TAG/$(echo $package | awk -F'/' '{print $2}')-$(basename $package) --all --authfile $OCP_PULLSECRET_AUTHFILE
  done
done

}

upgrade () {
# output ConfigMap for disconnected upgrade, issue guidance on mirroring

DIGEST="$(oc adm release info quay.io/openshift-release-dev/ocp-release:${OCP_RELEASE_FULL}-${ARCHITECTURE} | sed -n 's/Pull From: .*@//p')"
DIGEST_ALGO="${DIGEST%%:*}"
DIGEST_ENCODED="${DIGEST#*:}"
SIGNATURE_BASE64=$(curl -s "https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release/${DIGEST_ALGO}=${DIGEST_ENCODED}/signature-1" | base64 -w0 && echo)

cat > $SIGNATURE_BASE64_FILE << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: release-image-${OCP_RELEASE_FULL}
  namespace: openshift-config-managed
  labels:
    release.openshift.io/verification-signatures: ""
binaryData:
  ${DIGEST_ALGO}-${DIGEST_ENCODED}: ${SIGNATURE_BASE64}
EOF

echo ""
echo "To apply the image signature ConfigMap for $OCP_RELEASE_FULL, issue:"
echo "oc apply -f $SIGNATURE_BASE64_FILE"

echo ""
echo "To start mirroring content for OpenShift $OCP_RELEASE_FULL, issue:"
echo "oc adm release mirror --registry-config $OCP_PULLSECRET_AUTHFILE --from=quay.io/openshift-release-dev/ocp-release@$DIGEST --to=$LOCAL_REGISTRY$LOCAL_REGISTRY_MIRROR_TAG --to-release-image=$LOCAL_REGISTRY$LOCAL_REGISTRY_MIRROR_TAG:${OCP_RELEASE_FULL}-${ARCHITECTURE}"

echo ""
echo "To initiate the upgrade on the cluster to $OCP_RELEASE_FULL, issue:"
echo "oc adm upgrade --allow-explicit-upgrade --to-image $LOCAL_REGISTRY$LOCAL_REGISTRY_MIRROR_TAG@$DIGEST"
}

case "$1" in
	mirror)
		mirror
		;;
	mirror-olm)
		mirror-olm
		;;
	upgrade)
		upgrade
		;;
	*)
		echo $"Usage: $0 mirror|mirror-olm|upgrade"
		exit 1
esac

exit 0
```

### 创建 AgentServiceConfig 的例子
https://cloud.redhat.com/blog/telco-5g-zero-touch-provisioning-ztp<br>
https://github.com/openshift/assisted-service/blob/master/config/samples/agent-install.openshift.io_v1beta1_agentserviceconfig.yaml<br>
```
cat << EOF | oc apply -f - 
apiVersion: agent-install.openshift.io/v1beta1
kind: AgentServiceConfig
metadata:
  name: agent
  namespace: open-cluster-management
  ### This is the annotation that injects modifications in the Assisted Service pod
  annotations:
    unsupported.agent-install.openshift.io/assisted-service-configmap: "assisted-service-config"
###
spec:
  databaseStorage:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: 40Gi
  filesystemStorage:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: 40Gi
  osImages:
  - cpuArchitecture: x86_64
    openshiftVersion: '4.9'
    rootFSUrl: https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/rhcos-live-rootfs.x86_64.img
    url: https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/rhcos-4.9.0-x86_64-live.x86_64.iso
    version: 49.84.202110081407-0
EOF

## Private Key
ssh-keygen -t rsa -N '' -f ~/.ssh/acm_id_rsa
cp ~/.ssh/acm_id_rsa ~/tmp/
ACM_PRIVATE_KEY=~/tmp/acm_id_rsa
cat << EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: assisted-deployment-ssh-private-key
  namespace: open-cluster-management
stringData:
  ssh-privatekey: |-
$(cat ${ACM_PRIVATE_KEY})
type: Opaque
EOF

## Pull Secret
PULL_SECRET_FILE=~/tmp/redhat-pull-secret.json
PULL_SECRET_STR=$(cat ${PULL_SECRET_FILE} | jq -c .)
cat <<EOF | oc apply -f - 
apiVersion: v1
kind: Secret
metadata:
  name: assisted-deployment-pull-secret
  namespace: open-cluster-management
stringData:
  .dockerconfigjson: '${PULL_SECRET_STR}'
EOF

#  oc get secret assisted-deployment-pull-secret -o jsonpath="{.data.\.dockerconfigjson}" | base64 --decode

## AgentClusterInstall
## SNO Cluster Definition
## AgentClusterInstall
ACM_PUBLIC_STR=$(cat ~/.ssh/acm_id_rsa.pub)
cat << EOF | oc apply -f -
apiVersion: extensions.hive.openshift.io/v1beta1
kind: AgentClusterInstall
metadata:
  name: lab-cluster-aci
  namespace: open-cluster-management
spec:
  clusterDeploymentRef:
    name: lab-cluster
  imageSetRef:
    name: img4.9.9-x86-64-appsub
  networking:
    clusterNetwork:
      - cidr: "10.128.0.0/14"
        hostPrefix: 23
    serviceNetwork:
      - "172.31.0.0/16"
    machineNetwork:
      - cidr: "192.168.122.0/24"
  provisionRequirements:
    controlPlaneAgents: 1
  sshPublicKey: "${ACM_PUBLIC_STR}"
EOF

## ClusterDeployment
cat << EOF | oc apply -f -
apiVersion: hive.openshift.io/v1
kind: ClusterDeployment
metadata:
  name: lab-cluster
  namespace: open-cluster-management
spec:
  baseDomain: example.com
  clusterName: ocp4-1
  controlPlaneConfig:
    servingCertificates: {}
  installed: false
  clusterInstallRef:
    group: extensions.hive.openshift.io
    kind: AgentClusterInstall
    name: lab-cluster-aci
    version: v1beta1
  platform:
    agentBareMetal:
      agentSelector:
        matchLabels:
          bla: "aaa"
  pullSecretRef:
    name: assisted-deployment-pull-secret
EOF


## NMState Config
## https://bugzilla.redhat.com/show_bug.cgi?id=2030289
## https://docs.openshift.com/container-platform/4.9/scalability_and_performance/ztp-deploying-disconnected.html
## https://coreos.slack.com/archives/CUPJTHQ5P/p1628169479283900?thread_ts=1628081457.173400&cid=CUPJTHQ5P
cat << EOF | oc apply -f -
apiVersion: agent-install.openshift.io/v1beta1
kind: NMStateConfig
metadata:
  name: assisted-deployment-nmstate-lab-spoke
  labels:
    cluster-name: nmstate-lab-spoke
spec:
  config:
    dns-resolver:
      config:
        server:
        - 192.168.122.1
    interfaces:
    - name: ens3
      type: ethernet
      state: up
      ipv4:
        address:
        - ip: 192.168.122.201
          prefix-length: 24
        enabled: true
    routes:
      config:
      - destination: 0.0.0.0/0
        next-hop-address: 192.168.122.1
        next-hop-interface: ens3
        table-id: 254
  interfaces:
    - name: "ens3"
      macAddress: "52:54:00:1c:14:57"
EOF

## InfraEnv
cp ~/.ssh/acm_id_rsa.pub ~/tmp/
ACM_PUBLIC_KEY=~/tmp/acm_id_rsa.pub

cat << EOF | oc apply -f -
apiVersion: agent-install.openshift.io/v1beta1
kind: InfraEnv
metadata:
  name: lab-env
  namespace: open-cluster-management
spec:
  clusterRef:
    name: lab-cluster
    namespace: open-cluster-management
  sshAuthorizedKey: "$(cat ${ACM_PUBLIC_KEY})"
  agentLabelSelector:
    matchLabels:
      bla: "aaa"
  pullSecretRef:
    name: assisted-deployment-pull-secret
  nmStateConfigLabelSelector:
    matchLabels:
      cluster-name: nmstate-lab-spoke
EOF
oc get InfraEnv lab-env -o yaml


## SPOKE CLUSTER DEPLOYMENT
oc get pod -A | grep metal3

```


### 离线 OLM 与 operator
参考： https://zhimin-wen.medium.com/airgap-installation-for-openshift-operators-fb0a3cad8731<br>
参考：https://docs.oracle.com/en/operating-systems/oracle-linux/podman/skopeo-container-tool.html<br>
```
# 在 RHEL 8 上执行
创建定制化的 index image
podman pull registry.redhat.io/redhat/redhat-operator-index:v4.9 --authfile /data/OCP-4.9.9/ocp/secret/redhat-pull-secret.json
podman run -p50051:50051 --name operator-index -d registry.redhat.io/redhat/redhat-operator-index:v4.9

# 安装 grpcurl 工具
# https://github.com/fullstorydev/grpcurl/releases/download/v1.8.5/grpcurl_1.8.5_linux_x86_64.tar.gz
curl -L https://github.com/fullstorydev/grpcurl/releases/download/v1.8.5/grpcurl_1.8.5_linux_x86_64.tar.gz -o grpcurl_1.8.5_linux_x86_64.tar.gz
tar zxf grpcurl_1.8.5_linux_x86_64.tar.gz -C /usr/local/bin

# 获取 index image packages 信息
grpcurl -plaintext localhost:50051 api.Registry/ListPackages > packages.out

# 检查我们需要的 operator
# advanced-cluster-management,local-storage-operator,kubevirt-hyperconverged,submariner

# 生成 podman 本地 index image 
opm index prune -f registry.redhat.io/redhat/redhat-operator-index:v4.9 -p advanced-cluster-management,local-storage-operator,kubevirt-hyperconverged,submariner -t my-redhat-operator-index:v4.9

# 拷贝 podman 本地 index image 到 tar.gz 文件
skopeo copy containers-storage:localhost/my-redhat-operator-index:v4.9 docker-archive:my-redhat-operator-index-v4.9.tar.gz

# 拷贝 tar.gz 文件到 disconnected registry
skopeo copy --authfile /data/OCP-4.9.9/ocp/secret/redhat-pull-secret.json docker-archive:my-redhat-operator-index-v4.9.tar.gz docker://registry.example.com:5000/olm-mirror/my-redhat-operator-index:v4.9

# 将 catalog bundle 拷贝到目录
# v2/mirror/olm-mirror/my-redhat-operator-index
# 使用修剪的 image registry.example.com:5000/olm-mirror/my-redhat-operator-index:v4.9
# 将 catalog（metadata 和 image）保存到文件系统中
# 请注意，file://mirror 将映射到当前目录中的 v2/mirror 
mkdir -p /data/OCP-4.9.9/ocp/olm-mirror/redhat-operator-index
cd /data/OCP-4.9.9/ocp/olm-mirror/redhat-operator-index 
oc adm catalog mirror registry.example.com:5000/olm-mirror/my-redhat-operator-index:v4.9 file://mirror -a /data/OCP-4.9.9/ocp/secret/redhat-pull-secret.json
...
info: Mirroring completed in 5h39m40.14s (3.478MB/s)
error mirroring image: one or more errors occurred
wrote mirroring manifests to manifests-my-redhat-operator-index-1642043666

To upload local images to a registry, run:

        oc adm catalog mirror file://mirror/olm-mirror/my-redhat-operator-index:v4.9 REGISTRY/REPOSITORY

# 将目录上传到目标 registry
# 进入到包含 v2/mirror/olm-mirror/my-redhat-operator-index 中 v2 的目录
cd /data/OCP-4.9.9/ocp/olm-mirror/redhat-operator-index 
oc adm catalog mirror file://mirror/olm-mirror/my-redhat-operator-index:v4.9 registry.example.com:5000/olm-mirror -a /data/OCP-4.9.9/ocp/secret/redhat-pull-secret.json

```

### 将 StatefulSet 的启动命令改为循环
```
  containers:
  - name: command-demo-container
    image: debian
    command:
      - /bin/sh
    args:
      - "-c"
      - "while true ; do echo hello; sleep 10; done"
```

### zookeeper 报错 
https://blog.csdn.net/XiyouLinux_Kangyijie/article/details/76704639<br>
https://zookeeper.apache.org/doc/r3.1.2/zookeeperStarted.html<br>
```
zoo.cfg
zookeeper
Cannot assign requested address (Bind failed)
```

### cat 查看行号
```
cat -n filename
```

### 用命令检查 CrashLoopBack 状态容器
```
  containers:
  - name: command-demo-container
    image: debian
    command:
      - /bin/sh
    args:
      - "-c"
      - "while true ; do echo hello; sleep 10; done"
```

### 为 master 指定 ImageContentSourcePolicy
```
cat << EOF | oc --kubeconfig=/root/kubeconfig-ocp4-1 apply -f - 
apiVersion: operator.openshift.io/v1alpha1
kind: ImageContentSourcePolicy
metadata:
  name: openshift-release
spec:
  repositoryDigestMirrors:
  - mirrors:
    - registry.example.com:5000/ocp4/openshift4
    source: quay.io/openshift-release-dev/ocp-release
  - mirrors:
    - rregistry.example.com:5000/ocp4/openshift4
    source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
EOF

# 创建为内部 image-registry 准备的 pvc 
oc --kubeconfig=/root/kubeconfig-ocp4-1 create -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: registry-storage
  namespace: openshift-image-registry
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: 10Gi
EOF

# 将 SNO 原来的 configs.imageregistry.operator.openshift.io/cluster 的 /spec/storge 删除
# 然后添加 
# spec:
#   storage:
#     pvc:
#       claim: "registry-storage"
oc --kubeconfig=/root/kubeconfig-ocp4-1 patch configs.imageregistry.operator.openshift.io cluster --type=json --patch-file=/dev/fd/0 <<EOF
[{"op": "remove", "path": "/spec/storage" },{"op": "add", "path": "/spec/storage", "value": {"pvc":{"claim": "registry-storage"}}}]
EOF

# 将 configs.imageregistry.operator.openshift.io/cluster 的 spec.managemntState 设置为 Managed
# spec:
#   managementState: "Managed"
oc --kubeconfig=/root/kubeconfig-ocp4-1 patch configs.imageregistry.operator.openshift.io cluster --type merge --patch-file=/dev/fd/0 <<EOF
{"spec":{"managementState": "Managed"}}
EOF
```

### 报错 systemd[1]: Failed to start User Manager for UID 0.
https://access.redhat.com/solutions/5931241
```
Jan 14 05:58:59 master-0.ocp4-1.example.com systemd[1]: Failed to start User Manager for UID 0.

报错: oc get clusteroperators 
image-registry                             4.9.9     True        False         True       5m1s    ImagePrunerDegraded: Job has reached the specified backoff limit

清除报错
https://access.redhat.com/solutions/5370391

oc --kubeconfig=/root/kubeconfig-ocp4-1 patch imagepruner.imageregistry/cluster --patch '{"spec":{"suspend":true}}' --type=merge
oc --kubeconfig=/root/kubeconfig-ocp4-1 -n openshift-image-registry delete jobs --all
```

```
# 拷贝镜像
https://github.com/containers/skopeo/issues/1440

# 保存 rhacm2/agent-service-rhel8 到本地 registry，skopeo copy -a 命令可以拷贝全部数据
skopeo copy -a --authfile ${PULL_SECRET_FILE} --format v2s2 docker://registry.redhat.io/rhacm2/agent-service-rhel8@sha256:d738f808b7cf86c47d4c5a6c8ed5cb4387ca285123a393ec5f8d18951e4e0fb2 docker://registry.example.com:5000/rhacm2/agent-service-rhel8@sha256:d738f808b7cf86c47d4c5a6c8ed5cb4387ca285123a393ec5f8d18951e4e0fb2
skopeo copy -a --authfile ${PULL_SECRET_FILE} --format v2s2 docker://registry.redhat.io/rhel8/postgresql-12@sha256:952ac9a625c7600449f0ab1970fae0a86c8a547f785e0f33bfae4365ece06336 docker://registry.example.com:5000/rhel8/postgresql-12

cat << EOF | oc --kubeconfig=/root/kubeconfig-ocp4-1 apply -f - 
apiVersion: operator.openshift.io/v1alpha1
kind: ImageContentSourcePolicy
metadata:
  name: openshift-release
spec:
  repositoryDigestMirrors:
  - mirrors:
    - registry.example.com:5000/ocp4/openshift4
    source: quay.io/openshift-release-dev/ocp-release
  - mirrors:
    - registry.example.com:5000/ocp4/openshift4
    source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
  - mirrors:
    - registry.example.com:5000/rhacm2/agent-service-rhel8
    source: registry.redhat.io/rhacm2/agent-service-rhel8
  - mirrors:
    - registry.example.com:5000/rhel8/postgresql-12
    source: registry.redhat.io/rhel8/postgresql-12    
EOF

```

```
parted -s /dev/sdb mklabel msdos 
parted -s /dev/sdb unit mib mkpart primary 1 100%
parted -s /dev/sdb set 1 lvm on
pvcreate /dev/sdb1
vgextend rhel /dev/sdb1
lvextend -l +100%FREE /dev/rhel/root /dev/sdb1 
xfs_growfs /
```

### 重建 assisted-service pod postgresql 数据库
```
1. save a copy of agentserviceconfig
oc --kubeconfig=/root/kubeconfig-ocp4-1 get agentserviceconfig agent -o yaml > agentserviceconfig.backup

2.
oc --kubeconfig=/root/kubeconfig-ocp4-1 delete agentserviceconfig agent

3.
oc --kubeconfig=/root/kubeconfig-ocp4-1 create -f agentserviceconfig.backup
```

### assisted-service pod 服务检查
```
报错
time="2022-01-18T05:21:15Z" level=fatal msg="Failed to upload boot files" func=main.main.func1 file="/remote-source/assisted-service/app/cmd/main.go:179" error="Failed uploading boot files for OCP version 4.9: Failed fetching from URL http://192.168.122.15/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/rhcos-4.9.0-x86_64-live.x86_64.iso: Get \"http://192.168.122.15/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/rhcos-4.9.0-x86_64-live.x86_64.iso\": dial tcp 192.168.122.15:80: connect: no route to host"

问题解决
在 192.168.122.15 上开启防火墙
firewall-cmd --add-service=http
firewall-cmd --add-service=http --permanent

oc --kubeconfig=/root/kubeconfig-ocp4-1 project
Using project "open-cluster-management" on server "https://api.ocp4-1.example.com:6443".

oc --kubeconfig=/root/kubeconfig-ocp4-1 get infraenv

oc --kubeconfig=/root/kubeconfig-ocp4-1 get infraenv ocp4-2 -o yaml
...
status:
  agentLabelSelector:
    matchLabels:
      infraenvs.agent-install.openshift.io: ocp4-2
  conditions:
  - lastTransitionTime: "2022-01-18T05:38:01Z"
    message: 'Failed to create image: cluster does not exist: ocp4-2, check AgentClusterInstall
      conditions: name ocp4-2 in namespace open-cluster-management'
    reason: ImageCreationError
    status: Unknown
    type: ImageCreated

oc --kubeconfig=/root/kubeconfig-ocp4-1 get AgentClusterInstall
```

```
# google-chrome 执行时设置 host-resolver-rules 
nohup /usr/bin/google-chrome-stable --restore-last-session --host-resolver-rules="MAP api.ocp-edge-cluster-0.qe.redhat.com 10.46.46.12","MAP oauth-openshift.apps.ocp-edge-cluster-0.qe.lab.redhat.com 10.46.46.12","MAP console-openshift-console.apps.ocp-edge-cluster-0.qe.lab.redhat.com 10.46.46.12","MAP grafana-openshift-monitoring.apps.ocp-edge-cluster-0.qe.redhat.com 10.46.46.12","MAP thanos-querier-openshift-monitoring.apps.ocp-edge-cluster-0.qe.redhat.com 10.46.46.12","MAP prometheus-k8s-openshift-monitoring.apps.ocp-edge-cluster-0.qe.redhat.com 10.46.46.12","MAP alertmanager-main-openshift-monitoring.apps.ocp-edge-cluster-0.qe.redhat.com 10.46.46.12","MAP multicloud-console.apps.ocp-edge-cluster-0.qe.lab.redhat.com 10.46.46.12" &

# Baremetal Host 例子
cat 07_baremetal_host.yaml 

apiVersion: metal3.io/v1alpha1
kind: BareMetalHost
metadata:
  name: "bm-spoke-8-master"
  namespace: bm-spoke-8
  labels:
    infraenvs.agent-install.openshift.io: "bm-spoke-8"
  annotations:
    inspect.metal3.io: disabled
spec:
  online: true
  automatedCleaningMode: disabled
  bootMACAddress: E4:43:4B:BD:90:9A 
  bmc:
    address: idrac-virtualmedia+https://10.19.28.55/redfish/v1/Systems/System.Embedded.1
    credentialsName: "10.19.28.55"
    disableCertificateVerification: true

# Install RHEL 8 Hypervisor

# 启用 RHEL 8 EPEL
# https://docs.fedoraproject.org/en-US/epel/#_el8
subscription-manager repos --enable codeready-builder-for-rhel-8-$(arch)-rpms
dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

# 安装虚拟化组件
sudo dnf module install virt
sudo dnf install virt-install
sudo systemctl start libvirtd
sudo systemctl enable libvirtd

# 根据需要禁用虚拟网络的 DHCP，以下是在虚拟网络 default 上，禁止 DHCP 时的例子 
if(virsh net-dumpxml default | grep dhcp &>/dev/null); then
      virsh net-update default delete ip-dhcp-range "<range start='192.168.122.2' end='192.168.122.254'/>" --live --config || { echo "Unable to disable DHCP on default network"; return 1; }
fi

# 检查 kvm_intel 的 nested 是否启用，如果未启用则启用
sudo cat /sys/module/kvm_intel/parameters/nested
sudo sed -ie 's|^#options kvm_intel nested=1|options kvm_intel nested=1|' /etc/modprobe.d/kvm.conf 
sudo modprobe -r kvm_intel
sudo modprobe kvm_intel

# 创建虚拟机磁盘目录

mkdir -p /data/kvm
chcon --reference /var/lib/libvirt /data
chcon -R --reference /var/lib/libvirt/images /data/kvm
sudo chmod a+r /data

# RHEL 7
[root@undercloud ~]# cat > /tmp/ks.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart
network --device=eth0 --hostname=support.example.com --bootproto=static --ip=192.168.122.12 --netmask=255.255.255.0 --gateway=192.168.122.1 --nameserver=192.168.122.12
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal
kexec-tools
tar
%end
EOF

# RHEL 8
[root@undercloud ~]# cat > /tmp/ks.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart
network --device=enp1s0 --hostname=support.example.com --bootproto=static --ip=192.168.122.12 --netmask=255.255.255.0 --gateway=192.168.122.1 --nameserver=192.168.122.12
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
%end
EOF

qemu-img create -f qcow2 -o preallocation=metadata /data/kvm/jwang-support-openshift.qcow2 120G

# RHEL 7
virt-install --name=jwang-support-openshift --vcpus=1 --ram=2048 \
--disk path=/data/kvm/jwang-support-openshift.qcow2,bus=virtio,size=120 \
--os-variant rhel7.0 --network network=default,model=virtio \
--boot menu=on --location /data/isos/rhel-7.9-x86_64-dvd1.iso \
--console pty,target_type=serial \
--initrd-inject /tmp/ks.cfg \
--extra-args='inst.ks=file:/ks.cfg'

# RHEL 8
virt-install --name=jwang-support-openshift --vcpus=1 --ram=2048 \
--disk path=/data/kvm/jwang-support-openshift.qcow2,bus=virtio,size=120 \
--os-variant rhel8.0 --network network=default,model=virtio \
--boot menu=on --location /data/isos/rhel-8.4-x86_64-dvd.iso \
--console pty,target_type=serial \
--initrd-inject /tmp/ks.cfg \
--extra-args='inst.ks=file:/ks.cfg'

# RHEL8 访问虚拟机console
yum install cockpit
systemctl enable --now cockpit.socket
firewall-cmd --add-service=cockpit --permanent
firewall-cmd --reload
yum install -y cockpit-machines 

安装 vncserver
yum install -y tigervnc-server virt-viewer
vncserver :3
firewall-cmd --permanent --add-port=5900/tcp
firewall-cmd --permanent --add-port=5901/tcp
firewall-cmd --permanent --add-port=5902/tcp
firewall-cmd --permanent --add-port=5903/tcp
firewall-cmd --reload

# 登陆 support.example.com
# 设置OCP安装版本信息
export OCP_MAJOR_VER=4.9
export OCP_VER=4.9.9
echo ${OCP_VER}

# 创建离线介质目录
export OCP_PATH=/data/OCP-${OCP_VER}/ocp
export YUM_PATH=/data/OCP-${OCP_VER}/yum
mkdir -p ${OCP_PATH}/{app-image,ocp-client,ocp-image,ocp-installer,rhcos,secret}  ${YUM_PATH}

# 下载离线YUM源
# 登录订阅账户并绑定OpenShift订阅
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
export SUB_USER=XXXXX
set +o history
export SUB_PASSWD=XXXXX
subscription-manager register --force --user ${SUB_USER} --password ${SUB_PASSWD}
set -o history
subscription-manager refresh
subscription-manager list --available --matches 'Red Hat OpenShift Container Platform' | grep "Pool ID"
subscription-manager attach --pool=<ONE-POOL-ID>
subscription-manager config --rhsm.baseurl=https://china.cdn.redhat.com
subscription-manager refresh
yum clean all
yum makecache

# 开启订阅频道
# 关闭所有预先启用的yum频道
subscription-manager repos --disable="*"
# 仅启用与本次部署相关的yum源
subscription-manager repos \
    --enable="rhel-8-for-x86_64-baseos-rpms" \
    --enable="rhel-8-for-x86_64-appstream-rpms" \
    --enable="rhocp-${OCP_MAJOR_VER}-for-rhel-8-x86_64-rpms" 
# 批量下载软件包
yum -y install yum-utils 
for repo in $(subscription-manager repos --list-enabled | grep "Repo ID" | awk '{print $3}'); do
    reposync -n --delete --repoid ${repo} -p ${YUM_PATH} --download-metadata
done
# 检查下载后的软件包容量
du -lh ${YUM_PATH} --max-depth=1
# 压缩打包
cd ${YUM_PATH}
for dir in $(ls --indicator-style=none ${YUM_PATH}/); do
    tar -zcvf ${YUM_PATH}/${dir}.tar.gz ${dir}; 
done



# 生成 cluster bashrc
export OCP_CLUSTER_ID="ocp4-1"
cat << EOF >> ~/.bashrc-${OCP_CLUSTER_ID}
#######################################
setVAR(){
  if [ \$# = 0 ]
  then
    echo "USAGE: "
    echo "   setVAR VAR_NAME VAR_VALUE    # Set VAR_NAME with VAR_VALUE"
    echo "   setVAR VAR_NAME              # Delete VAR_NAME"
  elif [ \$# = 1 ]
  then
    sed -i "/\${1}/d" ~/.bashrc-${OCP_CLUSTER_ID}
source ~/.bashrc-${OCP_CLUSTER_ID}
unset \${1}
    echo \${1} is empty
  else
    sed -i "/\${1}/d" ~/.bashrc-${OCP_CLUSTER_ID}
    echo export \${1}=\"\${2}\" >> ~/.bashrc-${OCP_CLUSTER_ID}
source ~/.bashrc-${OCP_CLUSTER_ID}
echo \${1}="\${2}"
  fi
  echo ${VAR_NAME}
}
#######################################
EOF
source ~/.bashrc-${OCP_CLUSTER_ID}

# 设置变量
setVAR OCP_MAJOR_VER 4.9
setVAR OCP_VER 4.9.9
setVAR RHCOS_VER 4.9.0
setVAR YUM_PATH /data/OCP-${OCP_VER}/yum     #存放yum源的目录
setVAR OCP_PATH /data/OCP-${OCP_VER}/ocp     #存放OCP原始安装介质的目录

# 安装oc客户端
tar -xzf ${OCP_PATH}/ocp-client/openshift-client-linux-${OCP_VER}.tar.gz -C /usr/local/sbin/
oc version

# 配置本地临时YUM源
# 准备YUM源所需的文件
# 先解压缩文件，然后删除压缩文件
cd ${YUM_PATH}
for file in $(ls ${YUM_PATH}/*.tar.gz); do tar -zxvf ${file} -C ${YUM_PATH}/; done
rm -rf ${YUM_PATH}/*.tar.gz

# 配置本地临时YUM源
# RHEL7
cat << EOF > /etc/yum.repos.d/base.repo
[rhel-7-server]
name=rhel-7-server
baseurl=file://${YUM_PATH}/rhel-7-server-rpms
enabled=1
gpgcheck=0
EOF


# RHEL8
# 创建以下文件，配置本地临时YUM源
cat << EOF > /etc/yum.repos.d/local.repo
[rhel-8-for-x86_64-baseos-rpms]
name=rhel-8-for-x86_64-baseos-rpms
baseurl=file://${YUM_PATH}/rhel-8-for-x86_64-baseos-rpms
enabled=1
gpgcheck=0

[rhel-8-for-x86_64-appstream-rpms]
name=rhel-8-for-x86_64-appstream-rpms
baseurl=file://${YUM_PATH}/rhel-8-for-x86_64-appstream-rpms
enabled=1
gpgcheck=0
EOF
yum repolist

# 创建基于HTTP的YUM服务
# 安装Apache HTTP服务，并将http的端口修改为8080
yum -y install httpd
systemctl enable httpd --now
sed -i -e 's/Listen 80/Listen 8080/g' /etc/httpd/conf/httpd.conf
cat /etc/httpd/conf/httpd.conf |grep "Listen 8080"
# 注意：必须将yum目录所属首级目录/data以及所有子目录权限设为705，这样才能通过http访问。
chmod -R 705 /data
# 创建指向yum目录的httpd配置文件。
cat << EOF > /etc/httpd/conf.d/yum.conf
Alias /repo "${YUM_PATH}"
<Directory "${YUM_PATH}">
  Options +Indexes +FollowSymLinks
  Require all granted
</Directory>
<Location /repo>
  SetHandler None
</Location>
EOF
# 重新启动 httpd 服务，然后验证可以访问到repo目录
systemctl restart httpd
curl http://localhost:8080/repo/

# 安装配置DNS服务
# OpenShift 4建议的域名组成为：集群名+根域名 $OCP_CLUSTER_ID.$DOMAIN
# 对于etcd，OCP要求由etcd-$INDEX格式组成。本例中由于etcd安装于master上，因此etcd的域名实际也是指向各master节点。此外，etcd还需要_etcd-server-ssl._tcp.$CLUSTERDOMMAIN的SRV记录，用于master寻找etcd节点，该域名指向etcd节点。
# 安装BIND服务
yum -y install bind bind-utils
systemctl enable named --now
# 设置BIND配置文件
# 先备份原始BIND配置文件，然后修改BIND配置，并重新加载配置
cp /etc/named.conf{,_bak}
sed -i -e "s/listen-on port.*/listen-on port 53 { any; };/" /etc/named.conf
sed -i -e "s/allow-query.*/allow-query { any; };/" /etc/named.conf
rndc reload
grep -E 'listen-on port|allow-query' /etc/named.conf 
# 注意：如果有外部的解析需求，则请确保DNS服务器可以访问外网，并添加如下配置：
# 如果有外部的解析需求，则请确保DNS服务器可以访问外网，并添加如下配置：
sed -i '/recursion yes;/a \
        forward first; \
        forwarders { 114.114.114.114; 8.8.8.8; };' /etc/named.conf
sed -i -e "s/dnssec-enable.*/dnssec-enable no;/" /etc/named.conf
sed -i -e "s/dnssec-validation.*/dnssec-validation no;/" /etc/named.conf
rndc reload

# 配置Zone区域
# 设置DNS环境变量
setVAR DOMAIN example.com
setVAR OCP_CLUSTER_ID ocp4-1
setVAR BASTION_IP 192.168.122.13
setVAR SUPPORT_IP 192.168.122.12
setVAR DNS_IP 192.168.122.12
setVAR NTP_IP 192.168.122.12
setVAR YUM_IP 192.168.122.12
setVAR REGISTRY_IP 192.168.122.12
setVAR NFS_IP 192.168.122.12
setVAR LB_IP 192.168.122.12
setVAR BOOTSTRAP_IP 192.168.122.100
setVAR MASTER0_IP 192.168.122.101
setVAR MASTER1_IP 192.168.122.102
setVAR MASTER2_IP 192.168.122.103
setVAR WORKER0_IP 192.168.122.110
setVAR WORKER1_IP 192.168.122.111

# 添加解析Zone区域
# 执行以下命令添加3个解析ZONE（如果要执行多次，需要手动删除以前增加的内容），它们分别为：
# 域名后缀                解释
# example.com           集群内部域名后缀：集群内部所有节点的主机名均采用该域名后缀
# ocp4-1.example.com    OCP集群的域名，如本例中的集群名为ocp4-1，则域名为ocp4-1.example.com
# 168.192.in-addr.arpa  用于集群内所有节点的反向解析
cat >> /etc/named.rfc1912.zones << EOF
 
zone "${DOMAIN}" IN {
        type master;
        file "${DOMAIN}.zone";
        allow-transfer { any; };
};
 
zone "${OCP_CLUSTER_ID}.${DOMAIN}" IN {
        type master;
        file "${OCP_CLUSTER_ID}.${DOMAIN}.zone";
        allow-transfer { any; };
};
 
zone "168.192.in-addr.arpa" IN {
        type master;
        file "168.192.in-addr.arpa.zone";
        allow-transfer { any; };
};
 
EOF
# 创建example.com.zone区域配置文件
cat > /var/named/${DOMAIN}.zone << EOF
\$ORIGIN ${DOMAIN}.
\$TTL 1D
@           IN SOA  ${DOMAIN}. admin.${DOMAIN}. (
                                        0          ; serial
                                        1D         ; refresh
                                        1H         ; retry
                                        1W         ; expire
                                        3H )       ; minimum
 
@             IN NS                         dns.${DOMAIN}.
 
bastion       IN A                          ${BASTION_IP}
support       IN A                          ${SUPPORT_IP}
dns           IN A                          ${DNS_IP}
ntp           IN A                          ${NTP_IP}
yum           IN A                          ${YUM_IP}
registry      IN A                          ${REGISTRY_IP}
nfs           IN A                          ${NFS_IP}
 
EOF
cat /var/named/${DOMAIN}.zone
# 创建ocp4-1.example.com.zone区域配置文件
cat > /var/named/${OCP_CLUSTER_ID}.${DOMAIN}.zone << EOF
\$ORIGIN ${OCP_CLUSTER_ID}.${DOMAIN}.
\$TTL 1D
@           IN SOA  ${OCP_CLUSTER_ID}.${DOMAIN}. admin.${OCP_CLUSTER_ID}.${DOMAIN}. (
                                        0          ; serial
                                        1D         ; refresh
                                        1H         ; retry
                                        1W         ; expire
                                        3H )       ; minimum
 
@             IN NS                         dns.${DOMAIN}.
 
lb             IN A                          ${LB_IP}
 
api            IN A                          ${LB_IP}
api-int        IN A                          ${LB_IP}
*.apps         IN A                          ${LB_IP}
 
bootstrap      IN A                          ${BOOTSTRAP_IP}
 
master-0       IN A                          ${MASTER0_IP}
master-1       IN A                          ${MASTER1_IP}
master-2       IN A                          ${MASTER2_IP}
 
etcd-0         IN A                          ${MASTER0_IP}
etcd-1         IN A                          ${MASTER1_IP}
etcd-2         IN A                          ${MASTER2_IP}
 
worker-0       IN A                          ${WORKER0_IP}
worker-1       IN A                          ${WORKER1_IP}
 
_etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN}. 8640 IN SRV 0 10 2380 etcd-0.${OCP_CLUSTER_ID}.${DOMAIN}.
_etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN}. 8640 IN SRV 0 10 2380 etcd-1.${OCP_CLUSTER_ID}.${DOMAIN}.
_etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN}. 8640 IN SRV 0 10 2380 etcd-2.${OCP_CLUSTER_ID}.${DOMAIN}.
 
EOF
cat /var/named/${OCP_CLUSTER_ID}.${DOMAIN}.zone
# 创建168.192.in-addr.arpa.zone反向解析区域配置文件
# 注意：以下脚本中的反向IP如果有变化需要在此手动修改。
cat > /var/named/168.192.in-addr.arpa.zone << EOF
\$TTL 1D
@           IN SOA  ${DOMAIN}. admin.${DOMAIN}. (
                                        0       ; serial
                                        1D      ; refresh
                                        1H      ; retry
                                        1W      ; expire
                                        3H )    ; minimum
                                        
@                              IN NS       dns.${DOMAIN}.
 
13.122.168.192.in-addr.arpa.     IN PTR      bastion.${DOMAIN}.
 
12.122.168.192.in-addr.arpa.     IN PTR      support.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      dns.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      ntp.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      yum.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      registry.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      nfs.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      lb.${OCP_CLUSTER_ID}.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      api.${OCP_CLUSTER_ID}.${DOMAIN}.
12.122.168.192.in-addr.arpa.     IN PTR      api-int.${OCP_CLUSTER_ID}.${DOMAIN}.
 
100.122.168.192.in-addr.arpa.    IN PTR      bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}.
 
101.122.168.192.in-addr.arpa.    IN PTR      master-0.${OCP_CLUSTER_ID}.${DOMAIN}.
102.122.168.192.in-addr.arpa.    IN PTR      master-1.${OCP_CLUSTER_ID}.${DOMAIN}.
103.122.168.192.in-addr.arpa.    IN PTR      master-2.${OCP_CLUSTER_ID}.${DOMAIN}.
 
110.122.168.192.in-addr.arpa.    IN PTR      worker-0.${OCP_CLUSTER_ID}.${DOMAIN}.
111.122.168.192.in-addr.arpa.    IN PTR      worker-1.${OCP_CLUSTER_ID}.${DOMAIN}.
 
EOF
cat /var/named/168.192.in-addr.arpa.zone
# 重启BIND服务
# 重启BIND服务，然后检查没有错误日志。
systemctl restart named
rndc reload
journalctl -u named

# 将Support节点的DNS配置指向自己
nmcli c mod $(nmcli con show |awk 'NR==2{print}'|awk '{print $1}') ipv4.dns "${DNS_IP}"
systemctl restart NetworkManager
nmcli c show $(nmcli con show |awk 'NR==2{print}'|awk '{print $1}')| grep ipv4.dns

# 测试正反向DNS解析
# 正向解析测试
dig nfs.${DOMAIN} +short
dig support.${DOMAIN} +short 
dig yum.${DOMAIN} +short
dig registry.${DOMAIN} +short
dig ntp.${DOMAIN} +short
dig lb.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig api.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig api-int.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig *.apps.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig bastion.${DOMAIN} +short
dig bootstrap.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig master-0.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig etcd-0.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig master-1.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig etcd-1.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig master-2.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig etcd-2.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig worker-0.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig worker-1.${OCP_CLUSTER_ID}.${DOMAIN} +short
dig _etcd-server-ssl._tcp.${OCP_CLUSTER_ID}.${DOMAIN} SRV +short

# 反向解析测试
dig -x ${BASTION_IP} +short
dig -x ${SUPPORT_IP} +short
dig -x ${BOOTSTRAP_IP} +short
dig -x ${MASTER0_IP} +short
dig -x ${MASTER1_IP} +short
dig -x ${MASTER2_IP} +short
dig -x ${WORKER0_IP} +short
dig -x ${WORKER1_IP} +short

# 配置远程正式YUM源
# 配置Support节点的YUM源
# 删除临时yum源
setVAR YUM_DOMAIN yum.${DOMAIN}:8080

# RHEL7
cat > /etc/yum.repos.d/ocp.repo << EOF
[rhel-7-server]
name=rhel-7-server
baseurl=http://${YUM_DOMAIN}/repo/rhel-7-server-rpms/
enabled=1
gpgcheck=0
 
[rhel-7-server-extras] 
name=rhel-7-server-extras
baseurl=http://${YUM_DOMAIN}/repo/rhel-7-server-extras-rpms/
enabled=1
gpgcheck=0
 
[rhel-7-server-ose] 
name=rhel-7-server-ose
baseurl=http://${YUM_DOMAIN}/repo/rhel-7-server-ose-${OCP_MAJOR_VER}-rpms/
enabled=1
gpgcheck=0 
 
EOF

# RHEL8
mv /etc/yum.repos.d/local.repo{,.bak}
cat > /etc/yum.repos.d/ocp.repo << EOF
[rhel-8-for-x86_64-baseos-rpms]
name=rhel-8-for-x86_64-baseos-rpms
baseurl=http://${YUM_DOMAIN}/repo/rhel-8-for-x86_64-baseos-rpms/
enabled=1
gpgcheck=0
 
[rhel-8-for-x86_64-appstream-rpms] 
name=rhel-8-for-x86_64-appstream-rpms
baseurl=http://${YUM_DOMAIN}/repo/rhel-8-for-x86_64-appstream-rpms/
enabled=1
gpgcheck=0
 
[rhocp-4.9-for-rhel-8-x86_64-rpms] 
name=rhocp-4.9-for-rhel-8-x86_64-rpms
baseurl=http://${YUM_DOMAIN}/repo/rhocp-4.9-for-rhel-8-x86_64-rpms/
enabled=1
gpgcheck=0 
 
EOF
yum repolist

# 安装基础软件包，验证YUM源
# 在Support节点安装以下软件包，验证YUM源是正常的。
# RHEL7 
yum -y install wget git net-tools bridge-utils jq tree httpd-tools 
# RHEL8
yum -y install podman wget git net-tools jq tree httpd-tools 

# 部署NTP服务
# 注意：下文将Support节点当做OpenShift集群的NTP服务源。如果用户已经有NTP服务，可以忽略此节，并在安装OpenShift集群后将集群节点的时间服务指向已有的NTP服务。
# 设置正确的时区
timedatectl set-timezone Asia/Shanghai
timedatectl status | grep 'Time zone'
# 配置chrony服务
# RHEL 8.4最小化安装会安装chrony时间服务软件。我们先查看chrony服务状态：
systemctl status chronyd
# 备份原始chrony.conf配置文件，再修改配置文件
cp /etc/chrony.conf{,.bak}
sed -i -e "s/^server*/#&/g" \
       -e "s/^pool*/#&/g" \
       -e "s/#local stratum 10/local stratum 10/g" \
       -e "s/#allow 192.168.0.0\/16/allow all/g" \
       /etc/chrony.conf
cat >> /etc/chrony.conf << EOF
server ntp.${DOMAIN} iburst
EOF
cat /etc/chrony.conf
# 重启chrony服务
systemctl restart chronyd
# 检查chrony服务端启动
ps -auxw |grep chrony
ss -lnup |grep chronyd
chronyc sources -v

# 部署本地Docker Registry
# 该Docker Registry镜像库用于提供OCP安装过程所需的容器镜像。
# 创建Docker Registry相关目录
setVAR REGISTRY_PATH /data/registry            ## 容器镜像库存放的根目录
mkdir -p ${REGISTRY_PATH}/{auth,certs,data}

# 创建访问Docker Registry的证书
# 在 RHEL 8 服务器上创建，然后拷贝对应文件到 RHEL 7
openssl req -newkey rsa:4096 -nodes -sha256 -keyout ${REGISTRY_PATH}/certs/registry.key -x509 -days 3650 \
  -out ${REGISTRY_PATH}/certs/registry.crt \
  -addext "subjectAltName = DNS:registry.${DOMAIN}" \
  -subj "/C=CN/ST=BEIJING/L=BJ/O=REDHAT/OU=IT/CN=registry.${DOMAIN}/emailAddress=admin@${DOMAIN}"
openssl x509 -in ${REGISTRY_PATH}/certs/registry.crt -text | head -n 14

yum -y install docker-distribution
# 创建Registry认证凭据，允许用openshift/redhat登录。
htpasswd -bBc ${REGISTRY_PATH}/auth/htpasswd openshift redhat
cat ${REGISTRY_PATH}/auth/htpasswd
# 创建docker-distribution配置文件
setVAR REGISTRY_DOMAIN registry.${DOMAIN}:5000                  ## 容器镜像库的访问域名
cat << EOF > /etc/docker-distribution/registry/config.yml
version: 0.1
log:
  fields:
    service: registry
storage:
    cache:
        layerinfo: inmemory
    filesystem:
        rootdirectory: ${REGISTRY_PATH}/data
    delete:
        enabled: false
auth:
  htpasswd:
    realm: basic-realm
    path: ${REGISTRY_PATH}/auth/htpasswd
http:
    addr: 0.0.0.0:5000
    host: https://${REGISTRY_DOMAIN}
    tls:
      certificate: ${REGISTRY_PATH}/certs/registry.crt
      key: ${REGISTRY_PATH}/certs/registry.key
EOF
cat /etc/docker-distribution/registry/config.yml
# 启动Registry镜像库服务
systemctl enable --now docker-distribution
systemctl status docker-distribution

# 从本地访问Docker Registry 
cp ${REGISTRY_PATH}/certs/registry.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust
curl -u openshift:redhat https://${REGISTRY_DOMAIN}/v2/_catalog

# 从远程访问Docker Registry


# 导入OpenShift核心镜像到Docker Registry
setVAR REGISTRY_REPO ocp4/openshift4       ## 在Docker Registry中存放OpenShift核心镜像的Repository
# 如果生成证书时设置了 subjectAltName 不需要设置 GODEBUG
setVAR GODEBUG 509ignoreCN=0

# 安装镜像操作工具并登录Docker Registry
yum -y install podman skopeo 
setVAR PULL_SECRET_FILE ${OCP_PATH}/secret/redhat-pull-secret.json
podman login -u openshift -p redhat --authfile ${PULL_SECRET_FILE} ${REGISTRY_DOMAIN}
cat ${PULL_SECRET_FILE}
# 向Docker Registry导入OpenShift核心镜像
tar -xvf ${OCP_PATH}/ocp-image/ocp-image-${OCP_VER}.tar -C ${OCP_PATH}/ocp-image/
rm -f ${OCP_PATH}/ocp-image/ocp-image-${OCP_VER}.tar
setVAR REGISTRY_REPO 
oc image mirror -a ${PULL_SECRET_FILE} \
     --dir=${OCP_PATH}/ocp-image/mirror_${OCP_VER} file://openshift/release:${OCP_VER}* ${REGISTRY_DOMAIN}/${REGISTRY_REPO}
# 查看已经导入镜像库镜像数量，然后查看镜像信息。
curl -u openshift:redhat https://${REGISTRY_DOMAIN}/v2/_catalog
curl -u openshift:redhat -s https://${REGISTRY_DOMAIN}/v2/${REGISTRY_REPO}/tags/list |jq -M '.["tags"][]' | wc -l
curl -u openshift:redhat -s https://${REGISTRY_DOMAIN}/v2/${REGISTRY_REPO}/tags/list |jq -M '.["name"] + ":" + .["tags"][]' 
oc adm release info -a ${PULL_SECRET_FILE} "${REGISTRY_DOMAIN}/${REGISTRY_REPO}:${OCP_VER}-x86_64" | grep -A 200 -i "Images" 

# 部署HAProxy负载均衡服务
# 安装Haproxy
yum -y install haproxy
systemctl enable haproxy --now

# 添加haproxy.cfg配置文件
cat <<EOF > /etc/haproxy/haproxy.cfg
 
# Global settings
#---------------------------------------------------------------------
global
    maxconn     20000
    log         /dev/log local0 info
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    user        haproxy
    group       haproxy
    daemon
 
    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats
 
#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
#    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          300s
    timeout server          300s
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 20000
 
listen stats
    bind :9000
    mode http
    stats enable
    stats uri /
 
frontend  openshift-api-server-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:6443
    mode tcp
    option tcplog
    default_backend openshift-api-server-${OCP_CLUSTER_ID}
 
frontend  machine-config-server-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:22623
    mode tcp
    option tcplog
    default_backend machine-config-server-${OCP_CLUSTER_ID}
 
frontend  ingress-http-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:80
    mode tcp
    option tcplog
    default_backend ingress-http-${OCP_CLUSTER_ID}
 
frontend  ingress-https-${OCP_CLUSTER_ID}
    bind lb.${OCP_CLUSTER_ID}.${DOMAIN}:443
    mode tcp
    option tcplog
    default_backend ingress-https-${OCP_CLUSTER_ID}
 
backend openshift-api-server-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     bootstrap bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check
    server     master-1 master-1.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check
    server     master-2 master-2.${OCP_CLUSTER_ID}.${DOMAIN}:6443 check
 
backend machine-config-server-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     bootstrap bootstrap.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check
    server     master-0 master-0.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check
    server     master-1 master-1.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check
    server     master-2 master-2.${OCP_CLUSTER_ID}.${DOMAIN}:22623 check
 
backend ingress-http-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     worker-0 worker-0.${OCP_CLUSTER_ID}.${DOMAIN}:80 check
    server     worker-1 worker-1.${OCP_CLUSTER_ID}.${DOMAIN}:80 check
 
backend ingress-https-${OCP_CLUSTER_ID}
    balance source
    mode tcp
    server     worker-0 worker-0.${OCP_CLUSTER_ID}.${DOMAIN}:443 check
    server     worker-1 worker-1.${OCP_CLUSTER_ID}.${DOMAIN}:443 check
 
EOF
cat /etc/haproxy/haproxy.cfg

# 重启HAProxy服务, 然后检查HAProxy服务
systemctl restart haproxy
ss -lntp |grep haproxy

# 访问如下页面http://lb.ocp4-1.example.internal:9000/，确认每行颜色和下图一致。注意：为了能解析域名，运行浏览器所在节点需要将DNS设置到support节点的地址。

# 1. 安装 Assisted Install 服务
# 这个部分按照安装 openshift upi support 服务器来安装一台服务器
# hostname: ocpai.exmaple.com
# ip: 192.168.122.14/24
# gateway: 192.168.122.1
# nameserver: 192.168.122.12
# 生成 ks.cfg - ocp-ai
cat > /tmp/ks-ocp-ai.cfg <<'EOF'
lang en_US
keyboard us
timezone Asia/Shanghai --isUtc
rootpw $1$PTAR1+6M$DIYrE6zTEo5dWWzAp9as61 --iscrypted
#platform x86, AMD64, or Intel EM64T
reboot
text
cdrom
bootloader --location=mbr --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart
network --device=enp1s0 --hostname=ocpai.example.com --bootproto=static --ip=192.168.122.14 --netmask=255.255.255.0 --gateway=192.168.122.1 --nameserver=192.168.122.12
auth --passalgo=sha512 --useshadow
selinux --enforcing
firewall --enabled --ssh
skipx
firstboot --disable
%packages
@^minimal-environment
kexec-tools
tar
openssl-perl
%end
EOF

# 创建 jwang-ocp-ai 虚拟机，安装操作系统
qemu-img create -f qcow2 -o preallocation=metadata /data/kvm/jwang-ocp-ai.qcow2 120G
virt-install --name=jwang-ocp-ai --vcpus=1 --ram=2048 --disk path=/data/kvm/jwang-ocp-ai.qcow2,bus=virtio,size=100 --os-variant rhel8.0 --network network=default,model=virtio --boot menu=on --location /data/isos/rhel-8.4-x86_64-dvd.iso --initrd-inject /tmp/ks-ocp-ai.cfg --extra-args='ks=file:/ks-ocp-ai.cfg'

# 挂载 iso
virsh change-media jwang-ocp-ai sda --source /data/isos/rhel-8.4-x86_64-dvd.iso --insert --live
mount /dev/sr0 /mnt

# 生成本地 yum 源
cat > /etc/yum.repos.d/local.repo << EOF
[baseos]
name=baseos
baseurl=file:///mnt/BaseOS
enabled=1
gpgcheck=0

[appstream]
name=appstream
baseurl=file:///mnt/AppStream
enabled=1
gpgcheck=0
EOF

sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
setenforce 0

dnf install -y @container-tools
dnf groupinstall -y "Development Tools"
dnf install -y python3-pip socat make tmux git jq crun

tar zxvf /data/assisted-installer/assisted-service.tar.gz -C /root/ 
tar zxvf /data/assisted-installer/assisted-installer-cli.tar.gz -C /root/

# 加载镜像
tar zxvf /data/assisted-installer/assisted-installer-images.tar.gz -C /root/
cd /root
for i in assisted-installer-images/*.tar ; do podman load -i $i ; done

# 关闭防火墙
systemctl disable firewalld
systemctl mask firewalld
iptable -nL 

# 安装 httpd
yum install -y httpd
systemctl enable --now httpd

tar zxvf /data/assisted-installer/assisted-image-service-os-image.tar.gz -C /
curl localhost/pub/

# 拷贝 rhcos-4.9.0-x86_64-live-rootfs.x86_64.img 
cp /data/assisted-installer/rhcos-4.9.0-x86_64-live-rootfs.x86_64.img /var/www/html/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/

# 导入 assisted-image-service.tar 到 quay.io/edge-infrastructure/assisted-image-service-new
tar zxvf /data/assisted-installer/assisted-service-export.tar.gz -C /root/
cd /root/assisted-service-export/
podman import assisted-image-service.tar quay.io/edge-infrastructure/assisted-image-service-new -c CMD=/assisted-image-service -c ENV=DATA_DIR=/data -c ENV=PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd /root/assisted-service
cat onprem-environment | grep IMAGE

# 编辑 onprem-environment，检查以下配置
SERVICE_BASE_URL=http://192.168.122.14:8090
ASSISTED_SERVICE_HOST=127.0.0.1:8090
IMAGE_SERVICE_BASE_URL=http://192.168.122.14:8888
LISTEN_PORT=8888
OS_IMAGES=[{"openshift_version":"4.9","cpu_architecture":"x86_64","url":"http://192.168.122.14/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/rhcos-4.9.0-x86_64-live.x86_64.iso","rootfs_url":"http://192.168.122.14/pub/openshift-v4/dependencies/rhcos/4.9/4.9.0/rhcos-live-rootfs.x86_64.img","version":"49.84.202110081407-0"}]
RELEASE_IMAGES=[{"openshift_version":"4.9","cpu_architecture":"x86_64","url":"registry.example.com:5000/ocp4/openshift4:4.9.9-x86_64","version":"4.9.9","default":true}]
HW_VALIDATOR_REQUIREMENTS=[{"version":"default","master":{"cpu_cores":4,"ram_mib":16384,"disk_size_gb":120,"installation_disk_speed_threshold_ms":10,"network_latency_threshold_ms":100,"packet_loss_percentage":0},"worker":{"cpu_cores":2,"ram_mib":8192,"disk_size_gb":120,"installation_disk_speed_threshold_ms":10,"network_latency_threshold_ms":1000,"packet_loss_percentage":10},"sno":{"cpu_cores":8,"ram_mib":16384,"disk_size_gb":120,"installation_disk_speed_threshold_ms":10}}]

# 检查 Makefile deploy-onprem
deploy-onprem:
        # Format: ip:hostPort:containerPort | ip::containerPort | hostPort:containerPort | containerPort
        podman pod create --name assisted-installer -p 5432:5432,8000:8000,8090:8090,8080:8080,8888:8888
        podman run -dt --pod assisted-installer --env-file onprem-environment --pull always --name postgres $(PSQL_IMAGE)
        podman run -dt --pod assisted-installer --env-file onprem-environment --pull always -v $(PWD)/deploy/ui/nginx.conf:/opt/bitnami/nginx/conf/server_blocks/nginx.conf:z --name assisted-installer-ui $(ASSISTED_UI)
        podman run -dt --pod assisted-installer --env-file onprem-environment --pull always --restart always --name assisted-image-service $(IMAGE_SERVICE)
        podman run -dt --pod assisted-installer --env-file onprem-environment ${PODMAN_PULL_FLAG} --env DUMMY_IGNITION=$(DUMMY_IGNITION) --restart always --name assisted-service $(SERVICE)
        ./hack/retry.sh 90 2 "curl -f http://127.0.0.1:8090/ready"
        ./hack/retry.sh 60 10 "curl -f http://127.0.0.1:8888/health"

# 执行以下命令启动 pod
podman pod create --name assisted-installer -p 5432:5432,8000:8000,8090:8090,8080:8080,8888:8888
podman run -dt --pod assisted-installer --env-file onprem-environment --pull never --name postgres quay.io/centos7/postgresql-12-centos7:latest
podman run -dt --pod assisted-installer --env-file onprem-environment --pull never -v ./deploy/ui/nginx.conf:/opt/bitnami/nginx/conf/server_blocks/nginx.conf:z --name assisted-installer-ui quay.io/edge-infrastructure/assisted-installer-ui:latest
podman run -dt --pod assisted-installer --env-file onprem-environment --pull never --restart always --name assisted-image-service quay.io/edge-infrastructure/assisted-image-service-new:latest
podman run -dt --pod assisted-installer --env-file onprem-environment --pull never --env DUMMY_IGNITION="False" --restart always --name assisted-service quay.io/edge-infrastructure/assisted-service:latest

# curl -v https://subscription.rhn.redhat.com --cacert /etc/rhsm/ca/redhat-uep.pem

# podman pull 镜像时指定 loglevel 来获得调试信息
```