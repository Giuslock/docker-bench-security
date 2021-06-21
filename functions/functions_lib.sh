#!/bin/sh



container_images() {
  check_4
  check_4_1
  check_4_2
  check_4_3
  check_4_4
  check_4_5
  check_4_6
  check_4_7
  check_4_8
  check_4_9
  check_4_10
  check_4_11
  check_4_end
}

container_images_level1() {
  check_4
  check_4_1
  check_4_2
  check_4_3
  check_4_4
  check_4_6
  check_4_7
  check_4_9
  check_4_10
  check_4_end
}

container_runtime() {
  check_5
  check_running_containers
  check_5_1
  check_5_2
  check_5_3
  check_5_4
  check_5_5
  check_5_6
  check_5_7
  check_5_8
  check_5_9
  check_5_10
  check_5_11
  check_5_12
  check_5_13
  check_5_14
  check_5_15
  check_5_16
  check_5_17
  check_5_18
  check_5_19
  check_5_20
  check_5_21
  check_5_22
  check_5_23
  check_5_24
  check_5_25
  check_5_26
  check_5_27
  check_5_28
  check_5_29
  check_5_30
  check_5_31
  check_5_end
}

container_runtime_level1() {
  check_5
  check_running_containers
  check_5_1
  check_5_3
  check_5_4
  check_5_5
  check_5_6
  check_5_7
  check_5_8
  check_5_9
  check_5_10
  check_5_11
  check_5_12
  check_5_13
  check_5_14
  check_5_15
  check_5_16
  check_5_17
  check_5_18
  check_5_19
  check_5_20
  check_5_21
  check_5_24
  check_5_25
  check_5_26
  check_5_27
  check_5_28
  check_5_30
  check_5_31
  check_5_end
}



community_checks() {
  check_c
  check_c_1
  check_c_1_1
  check_c_2
  check_c_end
}

# CIS
cis() {
  container_images
  container_runtime
}

cis_level1() {
  container_images_level1
  container_runtime_level1
}

# Community contributed
community() {
  community_checks
}

# All
all() {
  cis
  community
}
