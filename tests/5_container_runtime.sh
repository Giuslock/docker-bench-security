#!/bin/sh

check_5() {
  logit ""
  local id="5"
  local desc="Container Runtime"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

check_running_containers() {
  # If containers is empty, there are no running containers
  if [ -z "$containers" ]; then
    info "  * No containers running, skipping Section 5"
    return
  fi
  # Make the loop separator be a new-line in POSIX compliant fashion
  set -f; IFS=$'
  '
}

check_5_1() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.1"
  local desc="Ensure that, if applicable, an AppArmor Profile is enabled"
  local remediation="If AppArmor is applicable for your Linux OS, you should enable it. Alternatively, Docker's default AppArmor policy can be used.1.Verify AppArmor is installed.2.Create or import a AppArmor profile for Docker containers.3.Enable enforcement of the policy.4.Start your Docker container using the customized AppArmor profile.You should run your container with the option: --security-opt=apparmor:PROFILENAME"
  local remediationImpact="The container will have the security controls defined in the AppArmor profile. It should be noted that if the AppArmor profile is misconfigured, this may cause issues with the operation of the container."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  no_apparmor_containers=""
  for c in $containers; do
    policy=$(docker inspect --format 'AppArmorProfile={{ .AppArmorProfile }}' "$c")

    if [ "$policy" = "AppArmorProfile=" ] || [ "$policy" = "AppArmorProfile=[]" ] || [ "$policy" = "AppArmorProfile=<no value>" ] || [ "$policy" = "AppArmorProfile=unconfined" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "     * No AppArmorProfile Found: $c"
        no_apparmor_containers="$no_apparmor_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "     * No AppArmorProfile Found: $c"
      no_apparmor_containers="$no_apparmor_containers $c"
    fi
  done
  # We went through all the containers and found none without AppArmor
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with no AppArmorProfile" "$no_apparmor_containers"
}

check_5_2() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.2"
  local desc="Ensure that, if applicable, SELinux security options are set"
  local remediation="Set the SELinux State. Set the SELinux Policy. Create or import a SELinux policy template for Docker containers. Start Docker in daemon mode with SELinux enabled. Start your Docker container using the security options.You should run your container with the option: --security-opt label=level:YourLabel"
  local remediationImpact="Any restrictions defined in the SELinux policy will be applied to your containers. It should be noted that if your SELinux policy is misconfigured, this may have an impact on the correct operation of the affected containers."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  no_securityoptions_containers=""
  for c in $containers; do
    policy=$(docker inspect --format 'SecurityOpt={{ .HostConfig.SecurityOpt }}' "$c")

    if [ "$policy" = "SecurityOpt=" ] || [ "$policy" = "SecurityOpt=[]" ] || [ "$policy" = "SecurityOpt=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "     * No SecurityOptions Found: $c"
        no_securityoptions_containers="$no_securityoptions_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "     * No SecurityOptions Found: $c"
      no_securityoptions_containers="$no_securityoptions_containers $c"
    fi
  done
  # We went through all the containers and found none without SELinux
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with no SecurityOptions" "$no_securityoptions_containers"
}

check_5_3() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.3"
  local desc="Ensure that Linux kernel capabilities are restricted within containers"
  local remediation="You could remove all the currently configured capabilities and then restore only the ones you specifically use: docker run --cap-drop=all --cap-add={<Capability 1>,<Capability 2>} <Run arguments> <Container Image Name or ID> <Command>"
  local remediationImpact="Restrictions on processes within a container are based on which Linux capabilities are in force. Removal of the NET_RAW capability prevents the container from creating raw sockets which is good security practice under most circumstances, but may affect some networking utilities."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  caps_containers=""
  for c in $containers; do
    container_caps=$(docker inspect --format 'CapAdd={{ .HostConfig.CapAdd}}' "$c")
    caps=$(echo "$container_caps" | tr "[:lower:]" "[:upper:]" | \
      sed 's/CAPADD/CapAdd/' | \
      sed -r "s/AUDIT_WRITE|CHOWN|DAC_OVERRIDE|FOWNER|FSETID|KILL|MKNOD|NET_BIND_SERVICE|NET_RAW|SETFCAP|SETGID|SETPCAP|SETUID|SYS_CHROOT|\s//g")

    if [ "$caps" != 'CapAdd=' ] && [ "$caps" != 'CapAdd=[]' ] && [ "$caps" != 'CapAdd=<no value>' ] && [ "$caps" != 'CapAdd=<nil>' ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "     * Capabilities added: $caps to $c"
        caps_containers="$caps_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "     * Capabilities added: $caps to $c"
      caps_containers="$caps_containers $c"
    fi
  done
  # We went through all the containers and found none with extra capabilities
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Capabilities added for containers" "$caps_containers"
}

check_5_4() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.4"
  local desc="Ensure that privileged containers are not used"
  local remediation="You should not run containers with the --privileged flag."
  local remediationImpact="If you start a container without the --privileged flag, it will not have excessive default capabilities."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  privileged_containers=""
  for c in $containers; do
    privileged=$(docker inspect --format '{{ .HostConfig.Privileged }}' "$c")

    if [ "$privileged" = "true" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "     * Container running in Privileged mode: $c"
        privileged_containers="$privileged_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "     * Container running in Privileged mode: $c"
      privileged_containers="$privileged_containers $c"
    fi
  done
  # We went through all the containers and found no privileged containers
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running in privileged mode" "$privileged_containers"
}

check_5_5() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.5"
  local desc="Ensure sensitive host system directories are not mounted on containers"
  local remediation="You should not mount directories which are security sensitive on the host within containers, especially in read-write mode.If sensitive directories are mounted in read-write mode, it could be possible to make changes to files within them. This has obvious security implications and should be avoided."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  # List of sensitive directories to test for. Script uses new-lines as a separator.
  # Note the lack of identation. It needs it for the substring comparison.
  sensitive_dirs='/
/boot
/dev
/etc
/lib
/proc
/sys
/usr'
  fail=0
  sensitive_mount_containers=""
  for c in $containers; do
    volumes=$(docker inspect --format '{{ .Mounts }}' "$c")
    if docker inspect --format '{{ .VolumesRW }}' "$c" 2>/dev/null 1>&2; then
      volumes=$(docker inspect --format '{{ .VolumesRW }}' "$c")
    fi
    # Go over each directory in sensitive dir and see if they exist in the volumes
    for v in $sensitive_dirs; do
      sensitive=0
      if echo "$volumes" | grep -e "{.*\s$v\s.*true\s.*}" 2>/tmp/null 1>&2; then
        sensitive=1
      fi
      if [ $sensitive -eq 1 ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          warn -s "$check"
          warn "     * Sensitive directory $v mounted in: $c"
          sensitive_mount_containers="$sensitive_mount_containers $c:$v"
          echo "#$remediation\n">>solutions/Dockerfile
          fail=1
          continue
        fi
        warn "     * Sensitive directory $v mounted in: $c"
        sensitive_mount_containers="$sensitive_mount_containers $c:$v"
      fi
    done
  done
  # We went through all the containers and found none with sensitive mounts
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with sensitive directories mounted" "$sensitive_mount_containers"
}

check_5_6() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.6"
  local desc="Ensure sshd is not run within containers"
  local remediation="Running SSH within the container increases the complexity of security managemen, you should uninstall the SSH daemon from the container and use docker exec to enter a container on the remote host.docker exec --interactive --tty <CONTAINER ID> sh OR docker attach <CONTAINER ID>"
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  ssh_exec_containers=""
  printcheck=0
  for c in $containers; do

    processes=$(docker exec "$c" ps -el 2>/dev/null | grep -c sshd | awk '{print $1}')
    if [ "$processes" -ge 1 ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "     * Container running sshd: $c"
        ssh_exec_containers="$ssh_exec_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        printcheck=1
      else
        warn "     * Container running sshd: $c"
        ssh_exec_containers="$ssh_exec_containers $c"
      fi
    fi

    exec_check=$(docker exec "$c" ps -el 2>/dev/null)
    if [ $? -eq 255 ]; then
        if [ $printcheck -eq 0 ]; then
          warn -s "$check"
          printcheck=1
        fi
      warn "     * Docker exec fails: $c"
      ssh_exec_containers="$ssh_exec_containers $c"
      fail=1
    fi

  done
  # We went through all the containers and found none with sshd
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with sshd/docker exec failures" "$ssh_exec_containers"
}

check_5_7() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.7"
  local desc="Ensure privileged ports are not mapped within containers"
  local remediation="Docker allows a container port to be mapped to a privileged port on the host if the user explicitly declares it. This is because containers are executed with NET_BIND_SERVICE Linux kernel capability which does not restrict privileged port mapping. The privileged ports receive and transmit various pieces of data which are security sensitive and allowing containers to use them is not in line with good security practice. You should not map container ports to privileged host ports when starting a container. You should also, ensure that there is no such container to host privileged port mapping declarations in the Dockerfile."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  privileged_port_containers=""
  for c in $containers; do
    # Port format is private port -> ip: public port
    ports=$(docker port "$c" | awk '{print $0}' | cut -d ':' -f2)

    # iterate through port range (line delimited)
    for port in $ports; do
      if [ -n "$port" ] && [ "$port" -lt 1024 ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          warn -s "$check"
          warn "     * Privileged Port in use: $port in $c"
          privileged_port_containers="$privileged_port_containers $c:$port"
          echo "#$remediation\n">>solutions/Dockerfile
          fail=1
          continue
        fi
        warn "     * Privileged Port in use: $port in $c"
        privileged_port_containers="$privileged_port_containers $c:$port"
      fi
    done
  done
  # We went through all the containers and found no privileged ports
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers using privileged ports" "$privileged_port_containers"
}

check_5_8() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.8"
  local desc="Ensure that only needed ports are open on the container"
  local remediation="The dockerfile for a container image defines the ports which are opened by default on a container instance. The list of ports are relevant to the application you are running within the container and should only be open if they are needed. You should ensure that the Dockerfile for each container image only exposes needed ports."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"
  echo "#$remediation\n">>solutions/Dockerfile

  note -c "$check"
  logcheckresult "NOTE"
}

check_5_9() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.9"
  local desc="Ensure that the host's network namespace is not shared"
  local remediation="When the networking mode on a container is set to --net=host , the container is not placed inside a separate network stack. Effectively, applying this option instructs Docker to not containerize the container's networking. The consequence of this is that the container lives
outside in the main Docker host and has full access to its network interfaces.You should not pass the --net=host option when starting any container."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  net_host_containers=""
  for c in $containers; do
    mode=$(docker inspect --format 'NetworkMode={{ .HostConfig.NetworkMode }}' "$c")

    if [ "$mode" = "NetworkMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "     * Container running with networking mode 'host': $c"
        net_host_containers="$net_host_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "     * Container running with networking mode 'host': $c"
      net_host_containers="$net_host_containers $c"
    fi
  done
  # We went through all the containers and found no Network Mode host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running with networking mode 'host'" "$net_host_containers"
}

check_5_10() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.10"
  local desc="Ensure that the memory usage for containers is limited"
  local remediation="By default a container can use all of the memory on the host. You can use memory limit mechanisms to prevent a denial of service occurring where one container consumes all of
the host’s resources and other containers on the same host are therefore not able to function. Having no limit on memory usage can lead to issues where one container can easily make the whole system unstable and as a result unusable.You should run the container with only as much memory as it requires by using the --memory argument."
  local remediationImpact="If correct memory limits are not set on each container, one process can expand its usage and cause other containers to run out of resources."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  mem_unlimited_containers=""
  for c in $containers; do
    memory=$(docker inspect --format '{{ .HostConfig.Memory }}' "$c")
    if docker inspect --format '{{ .Config.Memory }}' "$c" 2> /dev/null 1>&2; then
      memory=$(docker inspect --format '{{ .Config.Memory }}' "$c")
    fi

    if [ "$memory" = "0" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Container running without memory restrictions: $c"
        mem_unlimited_containers="$mem_unlimited_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Container running without memory restrictions: $c"
      mem_unlimited_containers="$mem_unlimited_containers $c"
    fi
  done
  # We went through all the containers and found no lack of Memory restrictions
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Container running without memory restrictions" "$mem_unlimited_containers"
}

check_5_11() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.11"
  local desc="Ensure that CPU priority is set appropriately on containers"
  local remediation="By default, CPU time is divided between containers equally. If you wish to control available CPU resources amongst container instances, you can use the CPU sharing feature. CPU sharing allows you to prioritize one container over others and prevents lower priority
containers from absorbing CPU resources which may be required by other processes. This
ensures that high priority containers are able to claim the CPU runtime they require.You should manage the CPU runtime between your containers dependent on their priority within your organization. To do so start the container using the --cpu-shares argument."
  local remediationImpact="If you do not correctly assign CPU thresholds, the container process may run out of resources and become unresponsive. If CPU resources on the host are not constrainted, CPU shares do not place any restrictions on individual resources."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  cpu_unlimited_containers=""
  for c in $containers; do
    shares=$(docker inspect --format '{{ .HostConfig.CpuShares }}' "$c")
    if docker inspect --format '{{ .Config.CpuShares }}' "$c" 2> /dev/null 1>&2; then
      shares=$(docker inspect --format '{{ .Config.CpuShares }}' "$c")
    fi

    if [ "$shares" = "0" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Container running without CPU restrictions: $c"
        cpu_unlimited_containers="$cpu_unlimited_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
      fi
      warn "      * Container running without CPU restrictions: $c"
      cpu_unlimited_containers="$cpu_unlimited_containers $c"
      
    fi
  done
  # We went through all the containers and found no lack of CPUShare restrictions
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running without CPU restrictions" "$cpu_unlimited_containers"
}

check_5_12() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.12"
  local desc="Ensure that the container's root filesystem is mounted as read only"
  local remediation="The container's root filesystem should be treated as a 'golden image' by using Docker run's --read-only option. This prevents any writes to the container's root filesystem at
container runtime and enforces the principle of immutable infrastructure.Enabling this option forces containers at runtime to explicitly define their data writing
strategy to persist or not persist their data.
This also reduces security attack vectors since the container instance's filesystem cannot
be tampered with or written to unless it has explicit read-write permissions on its
filesystem folder and directories. You should add a --read-only flag at a container's runtime to enforce the container's root filesystem being mounted as read only."
  local remediationImpact="Enabling --read-only at container runtime may break some container OS packages if a data writing strategy is not defined. You should define what the container's data should and should not persist at runtime in order to decide which strategy to use."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  fsroot_mount_containers=""
  for c in $containers; do
   read_status=$(docker inspect --format '{{ .HostConfig.ReadonlyRootfs }}' "$c")

    if [ "$read_status" = "false" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Container running with root FS mounted R/W: $c"
        fsroot_mount_containers="$fsroot_mount_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Container running with root FS mounted R/W: $c"
      fsroot_mount_containers="$fsroot_mount_containers $c"
    fi
  done
  # We went through all the containers and found no R/W FS mounts
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers running with root FS mounted R/W" "$fsroot_mount_containers"
}

check_5_13() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.13"
  local desc="Ensure that incoming container traffic is bound to a specific host interface"
  local remediation="If you have multiple network interfaces on your host machine, the container can accept
connections on exposed ports on any network interface. This might not be desirable and
may not be secured. In many cases a specific, desired interface is exposed externally and
services such as intrusion detection, intrusion prevention, firewall, load balancing, etc. are
all run by intention there to screen incoming public traffic. You should therefore not accept
incoming connections on any random interface, but only the one designated for this type of
traffic.You should bind the container port to a specific host interface on the desired host port. Example: docker run --detach --publish 10.2.3.4:49153:80 nginx In this example, the container port 80 is bound to the host port on 49153 and would accept incoming connection only from the 10.2.3.4 external interface."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  incoming_unbound_containers=""
  for c in $containers; do
    for ip in $(docker port "$c" | awk '{print $3}' | cut -d ':' -f1); do
      if [ "$ip" = "0.0.0.0" ]; then
        # If it's the first container, fail the test
        if [ $fail -eq 0 ]; then
          warn -s "$check"
          warn "      * Port being bound to wildcard IP: $ip in $c"
          incoming_unbound_containers="$incoming_unbound_containers $c:$ip"
          echo "#$remediation\n">>solutions/Dockerfile
          fail=1
          continue
        fi
        warn "      * Port being bound to wildcard IP: $ip in $c"
        incoming_unbound_containers="$incoming_unbound_containers $c:$ip"
      fi
    done
  done
  # We went through all the containers and found no ports bound to 0.0.0.0
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with port bound to wildcard IP" "$incoming_unbound_containers"
}

check_5_14() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.14"
  local desc="Ensure that the 'on-failure' container restart policy is set to '5'"
  local remediation="By using the --restart flag in the docker run command you can specify a restart policy for
how a container should or should not be restarted on exit.If you indefinitely keep trying to start the container, it could possibly lead to a denial of
service on the host. It could be an easy way to do a distributed denial of service attack
especially if you have many containers on the same host. Additionally, ignoring the exit
status of the container and always attempting to restart the container, leads to non-
investigation of the root cause behind containers getting terminated. If a container gets
terminated, you should investigate on the reason behind it instead of just attempting to
restart it indefinitely. You should use the on-failure restart policy to limit the number of
container restarts to a maximum of 5 attempts.If you wish a container to be automatically restarted, a sample command is docker run --detach --restart=on-failure:5 nginx"
  local remediationImpact="If this option is set, a container will only attempt to restart itself 5 times."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  maxretry_unset_containers=""
  for c in $containers; do
    policy=$(docker inspect --format MaximumRetryCount='{{ .HostConfig.RestartPolicy.MaximumRetryCount }}' "$c")

    if [ "$policy" != "MaximumRetryCount=5" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * MaximumRetryCount is not set to 5: $c"
        maxretry_unset_containers="$maxretry_unset_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        #echo "docker update --restart on-failure:5 $c">>solution.sh
        continue
      fi
      warn "      * MaximumRetryCount is not set to 5: $c"
      maxretry_unset_containers="$maxretry_unset_containers $c"
    fi
  done
     
  # We went through all the containers and they all had MaximumRetryCount=5
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with MaximumRetryCount not set to 5" "$maxretry_unset_containers"
}

check_5_15() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.15"
  local desc="Ensure that the host's process namespace is not shared"
  local remediation="The Process ID (PID) namespace isolates the process ID space, meaning that processes in
different PID namespaces can have the same PID. This creates process level isolation
between the containers and the host.t prevents system processes from
being visible, and allows process ids to be reused including PID 1 . If the host's PID
namespace is shared with containers, it would basically allow these to see all of the
processes on the host system. This reduces the benefit of process level isolation between
the host and the containers. Under these circumstances a malicious user who has access to
a container could get access to processes on the host itself, manipulate them, and even be
able to kill them. This could allow for the host itself being shut down, which could be
extremely serious, particularly in a multi-tenanted environment. You should not share the
host's process namespace with the containers running on it.You should not start a container with the --pid=host argument."
  local remediationImpact="Container processes cannot see processes on the host system."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  pidns_shared_containers=""
  for c in $containers; do
    mode=$(docker inspect --format 'PidMode={{.HostConfig.PidMode }}' "$c")

    if [ "$mode" = "PidMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Host PID namespace being shared with: $c"
        pidns_shared_containers="$pidns_shared_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Host PID namespace being shared with: $c"
      pidns_shared_containers="$pidns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with PidMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host PID namespace" "$pidns_shared_containers"
}

check_5_16() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.16"
  local desc="Ensure that the host's IPC namespace is not shared"
  local remediation="The IPC namespace provides separation of IPC between the host and containers. If the
host's IPC namespace is shared with the container, it would allow processes within the
container to see all of IPC communications on the host system. This would remove the
benefit of IPC level isolation between host and containers. An attacker with access to a
container could get access to the host at this level with major consequences. The IPC
namespace should therefore not be shared between the host and its containers.You should not start a container with the --ipc=host argument."
  local remediationImpact="Shared memory segments are used in order to accelerate interprocess communications, commonly in high-performance applications. If this type of application is containerized into multiple containers, you might need to share the IPC namespace of the containers in order to achieve high performance. Under these circumstances, you should still only share container specific IPC namespaces and not the host IPC namespace."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  ipcns_shared_containers=""
  for c in $containers; do
    mode=$(docker inspect --format 'IpcMode={{.HostConfig.IpcMode }}' "$c")

    if [ "$mode" = "IpcMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Host IPC namespace being shared with: $c"
        ipcns_shared_containers="$ipcns_shared_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Host IPC namespace being shared with: $c"
      ipcns_shared_containers="$ipcns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with IPCMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host IPC namespace" "$ipcns_shared_containers"
}

check_5_17() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.17"
  local desc="Ensure that host devices are not directly exposed to containers"
  local remediation="The --device option exposes host devices to containers and as a result of this, containers can directly access these devices. The the container would not need to run in privileged mode to access and manipulate them, as by default, the container is granted this type of
access. Additionally, it would possible for containers to remove block devices from the host.
You therefore should not expose host devices to containers directly.
If for some reason you wish to expose the host device to a container you should consider
which sharing permissions you wish to use on a case by case base as appropriate to your
organization:(r - read only, w - writable, m - mknod allowed)"
  local remediationImpact="You would not be able to use host devices directly within containers."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  hostdev_exposed_containers=""
  for c in $containers; do
    devices=$(docker inspect --format 'Devices={{ .HostConfig.Devices }}' "$c")

    if [ "$devices" != "Devices=" ] && [ "$devices" != "Devices=[]" ] && [ "$devices" != "Devices=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        info -c "$check"
        info "      * Container has devices exposed directly: $c"
        hostdev_exposed_containers="$hostdev_exposed_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      info "      * Container has devices exposed directly: $c"
      hostdev_exposed_containers="$hostdev_exposed_containers $c"
    fi
  done
  # We went through all the containers and found none with devices
  if [ $fail -eq 0 ]; then
    pass -c "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "INFO" "Containers with host devices exposed directly" "$hostdev_exposed_containers"
}

check_5_18() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.18"
  local desc="Ensure that the default ulimit is overwritten at runtime if needed"
  local remediation="ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits in a prudent fashion, protects against denial of service conditions. On occasion, legitimate users and processes can accidentally overuse system resources and cause systems be degraded or even unresponsive.
The default ulimit set at the Docker daemon level should be honored. If the default ulimit
settings are not appropriate for a particular container instance, you may override them as
an exception, but this should not be done routinely. If many of your container instances are
exceeding your ulimit settings, you should consider changing the default settings to
something that is more appropriate for your needs.You should only override the default ulimit settings if needed in a specific case."
  local remediationImpact="If ulimits are not set correctly, overutilization by individual containers could make the host system unusable."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  no_ulimit_containers=""
  for c in $containers; do
    ulimits=$(docker inspect --format 'Ulimits={{ .HostConfig.Ulimits }}' "$c")

    if [ "$ulimits" = "Ulimits=" ] || [ "$ulimits" = "Ulimits=[]" ] || [ "$ulimits" = "Ulimits=<no value>" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        info -c "$check"
        info "      * Container no default ulimit override: $c"
        no_ulimit_containers="$no_ulimit_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      info "      * Container no default ulimit override: $c"
      no_ulimit_containers="$no_ulimit_containers $c"
    fi
  done
  # We went through all the containers and found none without Ulimits
  if [ $fail -eq 0 ]; then
    pass -c "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "INFO" "Containers with no default ulimit override" "$no_ulimit_containers"
}

check_5_19() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.19"
  local desc="A shared mount is replicated at all mounts and changes made at any mount point are
propagated to all other mount points.
Mounting a volume in shared mode does not restrict any other container from mounting
and making changes to that volume.
As this is likely not a desirable option from a security standpoint, this feature should not be
used unless explicitly required.Ensure mount propagation mode is not set to shared"
  local remediation="Do not mount volumes in shared mode propagation."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  mountprop_shared_containers=""
  for c in $containers; do
    if docker inspect --format 'Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' "$c" | \
     grep shared 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Mount propagation mode is shared: $c"
        mountprop_shared_containers="$mountprop_shared_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Mount propagation mode is shared: $c"
      mountprop_shared_containers="$mountprop_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with shared propagation mode
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with shared mount propagation" "$mountprop_shared_containers"
}

check_5_20() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.20"
  local desc="Ensure that the host's UTS namespace is not shared "
  local remediation="Sharing the UTS namespace with the host provides full permission for each container to
change the hostname of the host. This is not in line with good security practice and should
not be permitted.You should not start a container with the --uts=host argument."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  utcns_shared_containers=""
  for c in $containers; do
    mode=$(docker inspect --format 'UTSMode={{.HostConfig.UTSMode }}' "$c")

    if [ "$mode" = "UTSMode=host" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Host UTS namespace being shared with: $c"
        utcns_shared_containers="$utcns_shared_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Host UTS namespace being shared with: $c"
      utcns_shared_containers="$utcns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with UTSMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host UTS namespace" "$utcns_shared_containers"
}

check_5_21() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.21"
  local desc="Ensurethe default seccomp profile is not Disabled "
  local remediation="A large number of system calls are exposed to every userland process with many of them
going unused for the entire lifetime of the process. Most of applications do not need all
these system calls and would therefore benefit from having a reduced set of available
system calls. Having a reduced set of system calls reduces the total kernel surface exposed
to the application and thus improvises application security.By default, seccomp profiles are enabled. You do not need to do anything unless you want to modify and use a modified seccomp profile."
  local remediationImpact="With Docker 1.10 and greater, the default seccomp profile blocks syscalls, regardless of -- cap-add passed to the container."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  seccomp_disabled_containers=""
  for c in $containers; do
    if docker inspect --format 'SecurityOpt={{.HostConfig.SecurityOpt }}' "$c" | \
      grep -E 'seccomp:unconfined|seccomp=unconfined' 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Default seccomp profile disabled: $c"
        seccomp_disabled_containers="$seccomp_disabled_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
      else
        warn "      * Default seccomp profile disabled: $c"
        seccomp_disabled_containers="$seccomp_disabled_containers $c"
      fi
    fi
  done
  # We went through all the containers and found none with default secomp profile disabled
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers with default seccomp profile disabled" "$seccomp_disabled_containers"
}

check_5_22() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.22"
  local desc="Ensure that docker exec commands are not used with the privileged option "
  local remediation="Using the --privileged option in docker exec commands gives extended Linux
capabilities to the command. This could potentially be an insecure practice, particularly
when you are running containers with reduced capabilities or with enhanced restrictions.You should not use the --privileged option in docker exec commands."
  local remediationImpact="If you need enhanced capabilities within a container, then run it with all the permissions it requires. These should be specified individually."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  note -c "$check"
  logcheckresult "NOTE"
}

check_5_23() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.23"
  local desc="Ensure that docker exec commands are not used with the user=root option "
  local remediation="Using the --user=root option in a docker exec command, executes it within the container
as the root user. This could potentially be insecure, particularly when you are running
containers with reduced capabilities or enhanced restrictions.
For example, if your container is running as a tomcat user (or any other non-root user), it
would be possible to run a command through docker exec as root with the --user=root
option. This could potentially be dangerous.You should not use the --user=root option in docker exec commands."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"
echo "#$remediation\n">>solutions/Dockerfile

  note -c "$check"
  logcheckresult "NOTE"
}

check_5_24() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.24"
  local desc="Ensure that cgroup usage is confirmed "
  local remediation="System administrators typically define cgroups in which containers are supposed to run. If
cgroups are not explicitly defined by the system administrator, containers run in the
docker cgroup by default.
At run time, it is possible to attach a container to a different cgroup other than the one
originally defined. This usage should be monitored and confirmed, as by attaching to a
different cgroup, excess permissions and resources might be granted to the container and
this can therefore prove to be a security risk.You should not use the --cgroup-parent option within the docker run command unless strictly required."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  unexpected_cgroup_containers=""
  for c in $containers; do
    mode=$(docker inspect --format 'CgroupParent={{.HostConfig.CgroupParent }}x' "$c")

    if [ "$mode" != "CgroupParent=x" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Confirm cgroup usage: $c"
        unexpected_cgroup_containers="$unexpected_cgroup_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Confirm cgroup usage: $c"
      unexpected_cgroup_containers="$unexpected_cgroup_containers $c"
    fi
  done
  # We went through all the containers and found none with UTSMode as host
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
    logcheckresult "WARN" "Containers using unexpected cgroup" "$unexpected_cgroup_containers"
}

check_5_25() {
  if [ -z "$containers" ]; then
    return
  fi
  local id="5.25"
  local desc="Ensure that the container is restricted from acquiring additional privileges "
  local remediation="A process can set the no_new_priv bit in the kernel and this persists across forks, clones
and execve. The no_new_priv bit ensures that the process and its child processes do not
gain any additional privileges via suid or sgid bits. This reduces the danger associated with
many operations because the possibility of subverting privileged binaries is lessened.You should start your container with the options: docker run --rm -it --security-opt=no-new-privileges ubuntu bash"
  local remediationImpact="The no_new_priv option prevents LSMs like SELinux from allowing processes to acquire new privileges."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  addprivs_containers=""
  for c in $containers; do
    if ! docker inspect --format 'SecurityOpt={{.HostConfig.SecurityOpt }}' "$c" | grep 'no-new-privileges' 2>/dev/null 1>&2; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Privileges not restricted: $c"
        addprivs_containers="$addprivs_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Privileges not restricted: $c"
      addprivs_containers="$addprivs_containers $c"
    fi
  done
  # We went through all the containers and found none with capability to acquire additional privileges
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers without restricted privileges" "$addprivs_containers"
}

check_5_26() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.26"
  local desc="Ensure that container health is checked at runtime "
  local remediation="If the container image you are using does not have a pre-defined HEALTHCHECK instruction,
use the --health-cmd parameter to check container health at runtime.
Based on the reported health status, remedial actions can be taken if necessary.You should run the container using the --health-cmd parameter."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  nohealthcheck_containers=""
  for c in $containers; do
    if ! docker inspect --format '{{ .Id }}: Health={{ .State.Health.Status }}' "$c" 2>/dev/null 1>&2; then
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Health check not set: $c"
        nohealthcheck_containers="$nohealthcheck_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Health check not set: $c"
      nohealthcheck_containers="$nohealthcheck_containers $c"
    fi
  done
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers without health check" "$nohealthcheck_containers"
}

check_5_27() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.27"
  local desc="Ensure that Docker commands always make use of the latest version of their image "
  local remediation="Multiple Docker commands such as docker pull , docker run etc. are known to have an
issue where by default, they extract the local copy of the image, if present, even though
there is an updated version of the image with the same tag in the upstream repository. This
could lead to using older images containing known vulnerabilites.You should use proper version pinning mechanisms (the <latest> tag which is assigned by default is still vulnerable to caching attacks) to avoid extracting cached older versions. Version pinning mechanisms should be used for base images, packages, and entire images. You can customize version pinning rules according to your requirements."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"
  echo "#$remediation\n">>solutions/Dockerfile
	
  info -c "$check"
  logcheckresult "INFO"
}

check_5_28() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.28"
  local desc="Ensure that the PIDs cgroup limit is used"
  local remediation="Attackers could launch a fork bomb with a single command inside the container. This fork
bomb could crash the entire system and would require a restart of the host to make the
system functional again. Using the PIDs cgroup parameter --pids-limit would prevent
this kind of attack by restricting the number of forks that can happen inside a container
within a specified time frame.Use --pids-limit flag with an appropriate value when launching the container."
  local remediationImpact="Set the PIDs limit value as appropriate. Incorrect values might leave containers unusable."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  nopids_limit_containers=""
  for c in $containers; do
    pidslimit="$(docker inspect --format '{{.HostConfig.PidsLimit }}' "$c")"

    if [ "$pidslimit" = "0" ] || [  "$pidslimit" = "<nil>" ] || [  "$pidslimit" = "-1" ]; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * PIDs limit not set: $c"
        nopids_limit_containers="$nopids_limit_containers $c"
        echo "#$remediation\n">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * PIDs limit not set: $c"
      nopids_limit_containers="$nopids_limit_containers $c"
    fi
  done
  # We went through all the containers and found all with PIDs limit
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers without PIDs cgroup limit" "$nopids_limit_containers"
}

check_5_29() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.29"
  local desc="Ensure that Docker's default bridge "docker0" is not used "
  local remediation="Docker connects virtual interfaces created in bridge mode to a common bridge called
docker0 . This default networking model is vulnerable to ARP spoofing and MAC flooding
attacks as there is no filtering applied to it.You should follow the Docker documentation and set up a user-defined network. All the containers should be run in this network."
  local remediationImpact="User-defined networks need to be configured and managed in line with organizational security policy."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  docker_network_containers=""
  networks=$(docker network ls -q 2>/dev/null)
  for net in $networks; do
    if docker network inspect --format '{{ .Options }}' "$net" 2>/dev/null | grep "com.docker.network.bridge.name:docker0" >/dev/null 2>&1; then
      docker0Containers=$(docker network inspect --format='{{ range $k, $v := .Containers }} {{ $k }} {{ end }}' "$net" | \
        sed -e 's/^ //' -e 's/  /\n/g' 2>/dev/null)

      if [ -n "$docker0Containers" ]; then
        if [ $fail -eq 0 ]; then
          info -c "$check"
          echo "#$remediation">>solutions/Dockerfile
          fail=1
        fi
        for c in $docker0Containers; do
          if [ -z "$exclude" ]; then
            cName=$(docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's/\///g')
          else
            pattern=$(echo "$exclude" | sed 's/,/|/g')
            cName=$(docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's/\///g' | grep -Ev "$pattern" )
          fi
          if [ -n "$cName" ]; then
            info "      * Container in docker0 network: $cName"
            docker_network_containers="$docker_network_containers $c:$cName"
          fi
        done
      fi
    fi
  done
  # We went through all the containers and found none in docker0 network
  if [ $fail -eq 0 ]; then
    pass -c "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "INFO" "Containers using docker0 network" "$docker_network_containers"
}

check_5_30() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.30"
  local desc="User namespaces ensure that a root process inside the container will be mapped to a non-
root process outside the container. Sharing the user namespaces of the host with the
container does not therefore isolate users on the host from users in the containers.Ensure that the host's user namespaces are not shared"
  local remediation="You should not share user namespaces between host and containers."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  hostns_shared_containers=""
  for c in $containers; do
    if docker inspect --format '{{ .HostConfig.UsernsMode }}' "$c" 2>/dev/null | grep -i 'host' >/dev/null 2>&1; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Namespace shared: $c"
        hostns_shared_containers="$hostns_shared_containers $c"
        echo "#$remediation">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Namespace shared: $c"
      hostns_shared_containers="$hostns_shared_containers $c"
    fi
  done
  # We went through all the containers and found none with host's user namespace shared
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing host user namespace" "$hostns_shared_containers"
}

check_5_31() {
  if [ -z "$containers" ]; then
    return
  fi

  local id="5.31"
  local desc="If the Docker socket is mounted inside a container it could allow processes running within
the container to execute Docker commands which would effectively allow for full control of
the host.Ensure that the Docker socket is not mounted inside any containers"
  local remediation="You should ensure that no containers mount docker.sock as a volume."
  local remediationImpact="None."
  local check="$id  - $desc"
  starttestjson "$id" "$desc"

  fail=0
  docker_sock_containers=""
  for c in $containers; do
    if docker inspect --format '{{ .Mounts }}' "$c" 2>/dev/null | grep 'docker.sock' >/dev/null 2>&1; then
      # If it's the first container, fail the test
      if [ $fail -eq 0 ]; then
        warn -s "$check"
        warn "      * Docker socket shared: $c"
        docker_sock_containers="$docker_sock_containers $c"
        echo "#$remediation">>solutions/Dockerfile
        fail=1
        continue
      fi
      warn "      * Docker socket shared: $c"
      docker_sock_containers="$docker_sock_containers $c"
    fi
  done
  # We went through all the containers and found none with docker.sock shared
  if [ $fail -eq 0 ]; then
    pass -s "$check"
    logcheckresult "PASS"
    return
  fi
  logcheckresult "WARN" "Containers sharing docker socket" "$docker_sock_containers"
}

check_5_end() {
  endsectionjson
}
