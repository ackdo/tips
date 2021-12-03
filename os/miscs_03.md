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
10.66.208.125   jwang-ceph04.example.com
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

# 为节点打标签 mds
ceph orch host label add jwang-ceph04.example.com mds

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

# 看看 cephfs mds 服务
ceph fs volume create cephfs
ceph orch apply mds cephfs --placement="1 jwang-ceph04.example.com"

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

        sudo /usr/sbin/cephadm shell --fsid 88946910-53f0-11ec-ab5a-001a4a16016f -c /etc/ceph/ceph.conf -k /etc/ceph/ceph.client.admin.keyr
ing

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
dmsetup remove ceph--55676940--281c--43fc--9b71--d359acecb778-osd--block--e0b08b95--d184--4dd8--9748--e495c5225caa
dmsetup remove ceph--9cb74522--f080--4e25--a6fa--3b6b8a893444-osd--block--82b96e58--bb69--4492--a320--993a963890c6

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
```