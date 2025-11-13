## Install runtimeclass

    $ kubectl apply -f https://github.com/edgelesssys/contrast/releases/download/v0.7.1/runtime.yml

    $ kubectl get pod --all-namespaces  | grep contrast
    kube-system    contrast-node-installer-978gr       1/1     Running   0          69m

    $ kubectl get runtimeclass
    NAME                                           HANDLER                                        AGE
    contrast-cc-73b9805c032589b19b48e4d388307874   contrast-cc-73b9805c032589b19b48e4d388307874   70m

    $ cat /etc/containerd/config.toml

    [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.contrast-cc-73b9805c032589b19b48e4d388307874]
    runtime_type = 'io.containerd.contrast-cc.v2'
    runtime_path = '/opt/edgeless/contrast-cc-73b9805c032589b19b48e4d388307874/bin/containerd-shim-contrast-cc-v2'
    pod_annotations = ['io.katacontainers.*']
    privileged_without_host_devices = true
    snapshotter = 'tardev'

    [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.contrast-cc-73b9805c032589b19b48e4d388307874.options]
    ConfigPath = '/opt/edgeless/contrast-cc-73b9805c032589b19b48e4d388307874/etc/configuration-clh-snp.toml'

    $ tree /opt/edgeless/
    /opt/edgeless/
    └── contrast-cc-73b9805c032589b19b48e4d388307874
        ├── bin
        │   ├── cloud-hypervisor-snp
        │   └── containerd-shim-contrast-cc-v2
        ├── etc
        │   └── configuration-clh-snp.toml
        └── share
            ├── kata-containers-igvm.img
            └── kata-containers.img

    $ cat /opt/edgeless/contrast-cc-73b9805c032589b19b48e4d388307874/etc/configuration-clh-snp.toml 
    ...
    igvm = '/opt/edgeless/contrast-cc-73b9805c032589b19b48e4d388307874/share/kata-containers-igvm.img'
    image = '/opt/edgeless/contrast-cc-73b9805c032589b19b48e4d388307874/share/kata-containers.img'
    kernel_params = ''
    path = '/opt/edgeless/contrast-cc-73b9805c032589b19b48e4d388307874/bin/cloud-hypervisor-snp'
    ...

## Download contrast, app and coordinator files.

    $ curl --proto '=https' --tlsv1.2 -fLo contrast https://github.com/edgelesssys/contrast/releases/download/v0.7.1/contrast

    $ curl -fLO https://github.com/edgelesssys/contrast/releases/download/v0.7.1/emojivoto-demo.zip
    $ unzip emojivoto-demo.zip

    $ curl --proto '=https' --tlsv1.2 -fLo coordinator.yml https://github.com/edgelesssys/contrast/releases/download/v0.7.1/coordinator.yml


## Contrast CLI

    $ ./contrast -h
    contrast

    Usage:
    [command]

    Available Commands:
    completion  Generate the autocompletion script for the specified shell
    generate    generate policies and inject into Kubernetes resources
    help        Help about any command
    runtime     Prints the runtimeClassName
    set         Set the given manifest at the coordinator
    verify      Verify a contrast deployment

    Flags:
    -h, --help                   help for this command
        --log-level string       set logging level (debug, info, warn, error, or a number) (default "warn")
    -v, --version                version for this command
        --workspace-dir string   directory to write files to, if not set explicitly to another location

    Use " [command] --help" for more information about a command.


    $ ./contrast generate -h
    Generate policies and inject into the given Kubernetes resources.

    This will add the Contrast Initializer and Contrast Service Mesh as init containers
    to your workloads and then download the referenced container images to calculate the
    dm-verity hashes of the image layers. In addition, the Rego policy will be used as
    base and updated with the given settings file. For each container workload, the
    policy is added as an annotation to the Kubernetes YAML.

    The hashes of the policies are added to the manifest.

    If the Kubernetes YAML contains a Contrast Coordinator pod whose policy differs from
    the embedded default, the generated policy will be printed to stdout, alongside a
    warning message on stderr. This hash needs to be passed to the set and verify
    subcommands.

    Usage:
       generate [flags] paths...

    Flags:
      -d, --disable-updates                  prevent further updates of the manifest
      -h, --help                             help for generate
      -m, --manifest string                  path to manifest (.json) file (default "manifest.json")
      -p, --policy string                    path to policy (.rego) file (default "rules.rego")
      -s, --settings string                  path to settings (.json) file (default "settings.json")
          --skip-initializer                 skip injection of Contrast Initializer
      -w, --workload-owner-key stringArray   path to workload owner key (.pem) file (default [workload-owner.pem])

        Global Flags:
            --log-level string       set logging level (debug, info, warn, error, or a number) (default "warn")
            --workspace-dir string   directory to write files to, if not set explicitly to another location


    $ ./contrast set -h
    Set the given manifest at the coordinator.

    This will connect to the given Coordinator using aTLS. During the connection
    initialization, the remote attestation of the Coordinator CVM happens and
    the connection will only be successful if the Coordinator conforms with the
    reference values embedded into the CLI.

    After the connection is established, the manifest is set. The Coordinator
    will re-generate the mesh CA certificate and accept new workloads to
    issuer certificates.

    Usage:
       set [flags] paths...

    Flags:
      -c, --coordinator string               endpoint the coordinator can be reached at
          --coordinator-policy-hash string   override the expected policy hash of the coordinator (default "a3bfe2d9484a54900766041957a702b33fab4e666dd44fff940c52a4b2140d14")
      -h, --help                             help for set
      -m, --manifest string                  path to manifest (.json) file (default "manifest.json")
          --workload-owner-key string        path to workload owner key (.pem) file (default "workload-owner.pem")

    Global Flags:
          --log-level string       set logging level (debug, info, warn, error, or a number) (default "warn")
          --workspace-dir string   directory to write files to, if not set explicitly to another location


    $ ./contrast verify -h
    Verify a contrast deployment.

    This will connect to the given Coordinator using aTLS. During the connection
    initialization, the remote attestation of the Coordinator CVM happens and
    the connection will only be successful if the Coordinator conforms with the
    reference values embedded into the CLI.

    After the connection is established, the CLI will request the manifest history,
    all policies, and the certificates of the Coordinator certificate authority.

    Usage:
       verify [flags]

    Flags:
      -c, --coordinator string               endpoint the coordinator can be reached at
          --coordinator-policy-hash string   override the expected policy hash of the coordinator (default "a3bfe2d9484a54900766041957a702b33fab4e666dd44fff940c52a4b2140d14")
      -h, --help                             help for verify
          --workspace-dir string             directory to write files to, if not set explicitly to another location (default "./verify")

    Global Flags:
          --log-level string   set logging level (debug, info, warn, error, or a number) (default "warn")


## Contrast generate
    $ contrast generate deployment/
    ✔️ Patched targets
    ✔️ Generated workload policy annotations
    ✔️ Updated manifest manifest.json

    $ ls -l
    -rw-r--r-- 1 niteesh niteesh      763 Jul  3 17:01 manifest.json
    -rw-r--r-- 1 niteesh niteesh      288 Jul  3 17:01 workload-owner.pem
    -rw-rw-r-- 1 niteesh niteesh     1668 Jul  3 17:01 layers-cache.json
    -rw-r--r-- 1 niteesh niteesh    38659 Jul  3 17:01 rules.rego
    -rw-r--r-- 1 niteesh niteesh    10179 Jul  3 17:01 settings.json

## Execution Policy documents
    $ cat coordinator.yml | grep policy | awk '{print $2}' | base64 --decode > policy_documents/coordinator_policy.json

    $ cat deployment/emojivoto-demo.yml | grep policy | head -1 |  awk '{print $2}'  | base64 --decode > policy_documents/emoji_policy.json
    $ cat deployment/emojivoto-demo.yml | grep policy | head -2 | tail -1 |  awk '{print $2}'  | base64 --decode > policy_documents/voting_policy.json
    $ cat deployment/emojivoto-demo.yml | grep policy | tail -1 |  awk '{print $2}'  | base64 --decode > policy_documents/web_policy.json

    $ cat policy_documents/emoji_policy.json | sha256sum
    1e3ea6613cde1866c7f33844c4a2523a92a16ddc801470d9ee28e570e61296bd -

    $ cat policy_documents/voting_policy.json | sha256sum
    a7a3469153dfe6975952934f15db8182422398763d0707ef842eee4c36317e3c  -

    $ cat policy_documents/web_policy.json | sha256sum
    caf92dfa701b8d7f321e2d504d39f2828f817e8455042814d6a4a6dc510496d9  -

## Manifest
    $ cat manifest.json
    {
      "Policies": {
        "1e3ea6613cde1866c7f33844c4a2523a92a16ddc801470d9ee28e570e61296bd": [
          "emoji",
          "*"
        ],
        "a7a3469153dfe6975952934f15db8182422398763d0707ef842eee4c36317e3c": [
          "voting",
          "*"
        ],
        "caf92dfa701b8d7f321e2d504d39f2828f817e8455042814d6a4a6dc510496d9": [
          "web",
          "*"
        ]
      },
      "ReferenceValues": {
        "SNP": {
          "MinimumTCB": {
            "BootloaderVersion": 3,
            "TEEVersion": 0,
            "SNPVersion": 8,
            "MicrocodeVersion": 115
          }
        },
        "TrustedMeasurement": "73b9805c032589b19b48e4d388307874e5e865ae01960772fa3287a011dd0b8d45cceb677741548892adfc997d6c7a5d"
      },
      "WorkloadOwnerKeyDigests": [
        "3d48c7e0e0144837caa5674db160802911b93df0518b04fdb4bebd6ac972f8e0"
      ]
    }

## Execution policy content of a workload:
    $ cd policy_documents/web_policy_data/ ; ls -l
    -rw-rw-r-- 1 niteesh niteesh  5098 Jul  5 16:20 policy_data_cont1_pause.json
    -rw-rw-r-- 1 niteesh niteesh  6975 Jul  5 16:20 policy_data_cont2_mesh.json
    -rw-rw-r-- 1 niteesh niteesh  7286 Jul  5 16:20 policy_data_cont3_init.json
    -rw-rw-r-- 1 niteesh niteesh  8542 Jul  5 16:20 policy_data_cont4_web.json
    -rw-rw-r-- 1 niteesh niteesh  3406 Jul  5 16:19 policy_data_rest.json
    -rw-rw-r-- 1 niteesh niteesh 38659 Jul  5 16:22 rules.rego

    $ grep verity_hash ../../layers-cache.json 
        "verity_hash": "10343123cbd169684d0fe509669efa19886de74aec92e75bc4ed933026275750"
        "verity_hash": "406bef2a80e81ea99bf35cde59021058698e3b5018a38725f9dd14fba806905d"
        "verity_hash": "5038c0106b2f8a7158a649747b5555594f254bb6fff720619596e8ed14f93087"
        "verity_hash": "48106a2bcb4b1621821f796d588724dee6e5b59ebb34ecd1cc10e289a2890e99"
        "verity_hash": "817250f1a3e336da76f5bd3fa784e1b26d959b9c131876815ba2604048b70c18"
        "verity_hash": "9fd400b039021dd1c68c93bc565fa85d49d1fb2a21b4f05c1b5743e965f0b74a"
        "verity_hash": "8300bfdea8a91f96cc527c431c74498f11f536c8c31e00abbb7e197f07d04284"
        "verity_hash": "4bb6828b2e4fd84a0e9061edc002ac872d505cc4fe70546f9a0a09ba2c9874c6"
        "verity_hash": "1ada456980f576e6493e0802ae15059e2cda746d72a86adc8682a779041837f4"

    $ grep -A 4 "kata-overlay"  *cont*
    policy_data_cont1_pause.json:          "fstype": "fuse3.kata-overlay",
    policy_data_cont1_pause.json-          "options": [
    policy_data_cont1_pause.json-            "5a5aad80055ff20012a50dc25f8df7a29924474324d65f7d5306ee8ee27ff71d",
    policy_data_cont1_pause.json-            "817250f1a3e336da76f5bd3fa784e1b26d959b9c131876815ba2604048b70c18"
    policy_data_cont1_pause.json-          ],
    --
    policy_data_cont2_mesh.json:          "fstype": "fuse3.kata-overlay",
    policy_data_cont2_mesh.json-          "options": [
    policy_data_cont2_mesh.json-            "34fe4d9d55fe8a2da3de4936a428a0ca7ce606711f1f71bafbae39e820c8bca9",
    policy_data_cont2_mesh.json-            "8300bfdea8a91f96cc527c431c74498f11f536c8c31e00abbb7e197f07d04284"
    policy_data_cont2_mesh.json-          ],
    --
    policy_data_cont3_init.json:          "fstype": "fuse3.kata-overlay",
    policy_data_cont3_init.json-          "options": [
    policy_data_cont3_init.json-            "ee2b979e25b59d093d29ed1a1a6eb18bd28e46a98b522d28c7a53e835213e571",
    policy_data_cont3_init.json-            "9fd400b039021dd1c68c93bc565fa85d49d1fb2a21b4f05c1b5743e965f0b74a"
    policy_data_cont3_init.json-          ],
    --
    policy_data_cont4_web.json:          "fstype": "fuse3.kata-overlay",
    policy_data_cont4_web.json-          "options": [
    policy_data_cont4_web.json-            "9a2c5fff90eb04ab0388840349d94b338775df49382a9ee79ddce787cbf51ae1:1b43d0e44d650e677cecca240c9a9eb3b1da9bdd8df17a384bb6716c122a720f:d7b7b6ff3f667ac59eda656e59ae1ae43578b9136d9d9becb5bb6c77af603d55:265da6fac301228c6da590576b33d04f0decf98acb16b21b0fc0cbd1e9c9e450",
    policy_data_cont4_web.json-            "48106a2bcb4b1621821f796d588724dee6e5b59ebb34ecd1cc10e289a2890e99:1ada456980f576e6493e0802ae15059e2cda746d72a86adc8682a779041837f4:406bef2a80e81ea99bf35cde59021058698e3b5018a38725f9dd14fba806905d:10343123cbd169684d0fe509669efa19886de74aec92e75bc4ed933026275750"
    policy_data_cont4_web.json-          ],




