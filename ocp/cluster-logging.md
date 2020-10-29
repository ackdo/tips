### OCP 4.5 如何设置 OpenShift Logging
参见：https://docs.openshift.com/container-platform/4.5/logging/cluster-logging-deploying.html

大致的步骤为：
1. 安装 ElasticSearch Operator 和 Cluster Logging Operator
2. 创建 Cluster Logging Instance
3. 验证安装是否正确
4. 手工创建 kibana index patterns 和 visualizations

```
创建 Cluster Logging Instance

apiVersion: "logging.openshift.io/v1"
kind: "ClusterLogging"
metadata:
  name: "instance" 
  namespace: "openshift-logging"
spec:
  managementState: "Managed"  
  logStore:
    type: "elasticsearch"  
    retentionPolicy: 
      application:
        maxAge: 1d
      infra:
        maxAge: 1d
      audit:
        maxAge: 1d
    elasticsearch:
      nodeCount: 3 
      storage:
        storageClassName: "nfs-storage-provisioner" 
        size: 10G
      redundancyPolicy: "SingleRedundancy"
  visualization:
    type: "kibana"  
    kibana:
      replicas: 1
  curation:
    type: "curator"
    curator:
      schedule: "30 3 * * *" 
  collection:
    logs:
      type: "fluentd"  
      fluentd: {}
```

```
确认安装是否正确
oc get pod -n openshift-logging --selector component=elasticsearch

确认 es status
oc get pod -n openshift-logging --selector component=elasticsearch --no-headers | awk '{print $1}' | while read i ; do oc exec -n openshift-logging -c elasticsearch  ${i} -- es_cluster_health ; done 

确认 cronjob 
oc -n openshift-logging get CronJob 

确认 es indices
oc get pod -n openshift-logging --selector component=elasticsearch --no-headers | awk '{print $1}' | while read i ; do oc exec -n openshift-logging -c elasticsearch  ${i} -- indices ; done

# 参考 Bug 1866490
# https://bugzilla.redhat.com/show_bug.cgi?id=1866490


```

```
手工创建 kibana index patterns 和 visualizations

# A user must have the cluster-admin role, the cluster-reader role, or both roles to list the infra and audit indices in Kibana.
$ oc auth can-i get pods/logs -n default
yes

# The audit logs are not stored in the internal OpenShift Container Platform Elasticsearch instance by default. To view the audit logs in Kibana, you must use the Log Forwarding API to configure a pipeline that uses the default output for audit logs.
# See: https://examples.openshift.pub/logging/forwarding-demo/
oc create -f - <<EOF
apiVersion: logging.openshift.io/v1alpha1
kind: LogForwarding
metadata:
  name: instance
  namespace: openshift-logging
spec:
  disableDefaultForwarding: true
  outputs:
    - name: fluentd-created-by-user
      type: forward
      endpoint: 'fluentd.fluentd.svc.cluster.local:24224'
  pipelines:
    - name: app-pipeline
      inputSource: logs.app
      outputRefs:
        - fluentd-created-by-user
    - name: infra-pipeline
      inputSource: logs.infra
      outputRefs:
        - fluentd-created-by-user
    - name: clo-default-audit-pipeline
      inputSource: logs.audit
      outputRefs:
        - fluentd-created-by-user
EOF

# 获取 logforwanding
oc -n openshift-logging get logforwarding $(oc get logforwarding -n openshift-logging -o jsonpath='{.items[0].metadata.name}{"\n"}') -o yaml

# In the OpenShift Container Platform console, click the Application Launcher app launcher and select Logging.

# Create your Kibana index patterns by clicking Management → Index Patterns → Create index pattern:
## Users must manually create index patterns to see logs for their projects. Users should create a new index pattern named app and use the @timestamp time field to view their container logs.
## Admin users must create index patterns for the app, infra, and audit indices using the @timestamp time field.

# Create Kibana Visualizations from the new index patterns.
https://bugzilla.redhat.com/show_bug.cgi?id=1867137<br>
https://docs.openshift.com/container-platform/4.5/logging/cluster-logging-upgrading.html<br>


```