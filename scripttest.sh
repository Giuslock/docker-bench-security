#!/bin/sh

# Default values
if [ ! -d log ]; then
  mkdir log
fi
logger="log/${myname}.log"
limit=0
printremediation="1"
globalRemediation=""

check_security() {
  logit ""
  local id="5"
  local desc="Container Runtime"
  checkHeader="$id - $desc"
  info "$checkHeader"
  startsectionjson "$id" "$desc"
}

# If there is a container with label docker_bench_security, memorize it:
  benchcont="nil"
  for c in $(docker ps | sed '1d' | awk '{print $NF}'); do
    if docker inspect --format '{{ .Config.Labels }}' "$c" | \
     grep -e 'docker.bench.security' >/dev/null 2>&1; then
      benchcont="$c"
    fi
  done

containers=$(docker ps | sed '1d' | awk '{print $NF}' | grep -v "$benchcont")
    images=$(docker images -q | grep -v "$benchcont")
    
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
  local desc="Ensure that, if applicable, an AppArmor Profile is enabled (Scored)"
  local remediation="If AppArmor is applicable for your Linux OS, you should enable it. Alternatively, Docker's default AppArmor policy can be used."
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
  local desc="Ensure that, if applicable, SELinux security options are set (Scored)"
  local remediation="Set the SELinux State. Set the SELinux Policy. Create or import a SELinux policy template for Docker containers. Start Docker in daemon mode with SELinux enabled. Start your Docker container using the security options."
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


check_5_end() {
  endsectionjson
}
