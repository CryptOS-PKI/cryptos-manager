package main

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import "os"

// replicaLockNameEnv names the single-replica guard (#194) used in storage
// mode memory. The chart sets it to a name scoped to the Helm release, so two
// independent fleet-manager installs in the same Kubernetes namespace don't
// contend for the same lock.
const replicaLockNameEnv = "MANAGER_REPLICA_LOCK_NAME"

// defaultReplicaLockName is used outside the chart (bare host, Docker
// Compose), where there is normally only one fleet-manager deployment per
// data directory or per namespace anyway.
const defaultReplicaLockName = "cryptos-fleet-manager"

// replicaLockName is the single-replica guard's name: MANAGER_REPLICA_LOCK_NAME
// when set, defaultReplicaLockName otherwise.
func replicaLockName() string {
	if v := os.Getenv(replicaLockNameEnv); v != "" {
		return v
	}
	return defaultReplicaLockName
}
