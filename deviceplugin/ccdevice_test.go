// Copyright 2023 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deviceplugin

import (
	"context"
	"crypto/sha1"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

// ==========================================
// Part 1: Globals
// ==========================================
// Note: If you encounter "redeclared in this block" errors with plugin_test.go,
// ensure plugin_test.go does not define these variables, or remove them from one file.
const (
	ccResourceName = "test.google.com/cc"
	testBuffer     = 3 * time.Second
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowInfo())
	logger = log.With(logger, "timestamp", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)
}

// ==========================================
// Part 2: Test Helpers (Direct Construction)
// ==========================================

// constructTestPlugin creates a *CcDevicePlugin directly (bypassing the gRPC wrapper)
// This allows us to test the internal logic (discover/allocate) easily without networking.
func constructTestPlugin(t *testing.T, spec *CcDeviceSpec) *CcDevicePlugin {
	// Create a temporary directory for this specific test
	tmpDir := t.TempDir()

	// Create dummy device files based on the spec
	for _, path := range spec.DevicePaths {
		// Ensure parent dir exists (handles cases like /tmp/dev/tdx)
		err := os.MkdirAll(filepath.Dir(path), 0755)
		if err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("failed to create mock device: %v", err)
		}
		f.Close()
	}

	// Create dummy measurement files if needed
	for _, path := range spec.MeasurementPaths {
		err := os.MkdirAll(filepath.Dir(path), 0755)
		if err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("failed to create mock measurement: %v", err)
		}
		f.WriteString("dummy_measurement_data")
		f.Close()
	}

	// Initialize the struct directly
	cdp := &CcDevicePlugin{
		cds:                        spec,
		ccDevices:                  make(map[string]CcDevice),
		logger:                     logger,
		copiedEventLogDirectory:    filepath.Join(tmpDir, "copied_measurements"),
		copiedEventLogLocation:     filepath.Join(tmpDir, "copied_measurements", "binary_bios_measurements"),
		containerEventLogDirectory: "/run/cc-device-plugin",
		deviceGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cc_device_plugin_devices",
			Help: "The number of cc devices managed by this device plugin.",
		}),
		allocationsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cc_device_plugin_allocations_total",
			Help: "The total number of cc device allocations made by this device plugin.",
		}),
	}

	// Create the directory for copied measurements
	os.MkdirAll(cdp.copiedEventLogDirectory, 0755)

	return cdp
}

// ==========================================
// Part 3: Test Cases
// ==========================================

// TestDiscoverTDX verifies discovery of a device WITHOUT measurement files (e.g., TDX, SNP).
func TestDiscoverTDX(t *testing.T) {
	tmpDir := t.TempDir()
	devPath := filepath.Join(tmpDir, "tdx-guest")

	spec := &CcDeviceSpec{
		Resource:         "intel.com/tdx",
		DevicePaths:      []string{devPath},
		MeasurementPaths: []string{},
	}

	cdp := constructTestPlugin(t, spec)

	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 1 {
		t.Errorf("Expected 1 device, got %d", len(devices))
	}

	// Critical Check: TDX/SNP should NOT have mounts if no measurement file exists
	if len(devices[0].Mounts) != 0 {
		t.Errorf("TDX should have 0 mounts, got %d", len(devices[0].Mounts))
	}

	if devices[0].DeviceSpecs[0].HostPath != devPath {
		t.Errorf("HostPath mismatch. Got %s, Want %s", devices[0].DeviceSpecs[0].HostPath, devPath)
	}
}

// TestDiscoverTPM verifies discovery of a device WITH measurement files (legacy behavior).
func TestDiscoverTPM(t *testing.T) {
	tmpDir := t.TempDir()
	devPath := filepath.Join(tmpDir, "tpmrm0")
	measPath := filepath.Join(tmpDir, "binary_bios_measurements")

	spec := &CcDeviceSpec{
		Resource:         "google.com/cc",
		DevicePaths:      []string{devPath},
		MeasurementPaths: []string{measPath},
	}

	cdp := constructTestPlugin(t, spec)

	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 1 {
		t.Errorf("Expected 1 device, got %d", len(devices))
	}

	// Critical Check: TPM MUST have mounts for the measurement file
	if len(devices[0].Mounts) == 0 {
		t.Errorf("TPM should have mounts for measurement file, got 0")
	}
}

// TestDiscoverMultiplePaths verifies behavior when multiple device paths match (e.g., /dev/tdx1 and /dev/tdx2).
// According to current logic, they should be aggregated into ONE logical resource with multiple DeviceSpecs.
func TestDiscoverMultiplePaths(t *testing.T) {
	tmpDir := t.TempDir()
	devPath1 := filepath.Join(tmpDir, "tdx-guest-1")
	devPath2 := filepath.Join(tmpDir, "tdx-guest-2")

	spec := &CcDeviceSpec{
		Resource:         "intel.com/tdx",
		DevicePaths:      []string{devPath1, devPath2}, // Both paths exist
		MeasurementPaths: []string{},
	}

	cdp := constructTestPlugin(t, spec)

	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	// We expect 1 Logical Device (Resource) ...
	if len(devices) != 1 {
		t.Errorf("Expected 1 logical device, got %d", len(devices))
	}

	// ... containing 2 DeviceSpecs (one for each path)
	if len(devices[0].DeviceSpecs) != 2 {
		t.Errorf("Expected 2 DeviceSpecs (paths), got %d", len(devices[0].DeviceSpecs))
	}
}

// TestAllocate verifies the Allocate flow works for a generic device (SNP example).
func TestAllocate(t *testing.T) {
	tmpDir := t.TempDir()
	devPath := filepath.Join(tmpDir, "sev-guest")
	spec := &CcDeviceSpec{
		Resource:    "amd.com/sev-snp",
		DevicePaths: []string{devPath},
	}
	cdp := constructTestPlugin(t, spec)

	// Must refresh to populate the map
	cdp.refreshDevices()

	// Generate the expected ID manually (SHA1 of resource name)
	h := sha1.New()
	h.Write([]byte(spec.Resource))
	expectedID := fmt.Sprintf("%x", h.Sum(nil))

	req := &v1beta1.AllocateRequest{
		ContainerRequests: []*v1beta1.ContainerAllocateRequest{{
			DevicesIDs: []string{expectedID},
		}},
	}

	resp, err := cdp.Allocate(context.Background(), req)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	if len(resp.ContainerResponses) != 1 {
		t.Errorf("Expected 1 container response")
	}

	if resp.ContainerResponses[0].Devices[0].HostPath != devPath {
		t.Errorf("Allocation HostPath mismatch. Got %s, Want %s", resp.ContainerResponses[0].Devices[0].HostPath, devPath)
	}
}

// TestAllocateNotExistDevice verifies defensive programming against bad IDs.
func TestAllocateNotExistDevice(t *testing.T) {
	spec := &CcDeviceSpec{Resource: "test", DevicePaths: []string{}}
	cdp := constructTestPlugin(t, spec)

	req := &v1beta1.AllocateRequest{
		ContainerRequests: []*v1beta1.ContainerAllocateRequest{{
			DevicesIDs: []string{"invalid-id-that-does-not-exist"},
		}},
	}

	_, err := cdp.Allocate(context.Background(), req)

	if err == nil {
		t.Fatal("Expected error for non-existent device, got nil")
	}
	expectedErr := `requested cc device does not exist "invalid-id-that-does-not-exist"`
	if err.Error() != expectedErr {
		t.Errorf("Error message mismatch. Got %q, Want %q", err.Error(), expectedErr)
	}
}

// TestRefreshDevices verifies the lifecycle of device updates (New, Same, Removed).
func TestRefreshDevices(t *testing.T) {
	tmpDir := t.TempDir()
	devPath := filepath.Join(tmpDir, "tdx-guest")

	spec := &CcDeviceSpec{
		Resource:    "intel.com/tdx",
		DevicePaths: []string{devPath},
	}
	cdp := constructTestPlugin(t, spec)

	// 1. First Refresh (Device exists)
	changed, err := cdp.refreshDevices()
	if err != nil {
		t.Fatalf("First refresh failed: %v", err)
	}
	// The map should now contain the device
	if len(cdp.ccDevices) != 1 {
		t.Errorf("Expected 1 device in map, got %d", len(cdp.ccDevices))
	}

	// 2. Second Refresh (No change)
	changed, err = cdp.refreshDevices()
	if err != nil {
		t.Fatalf("Second refresh failed: %v", err)
	}
	// refreshDevices returns TRUE if devices are "same as before" (unchanged)
	if !changed {
		t.Errorf("Expected changed=true (unchanged), got false")
	}

	// 3. Third Refresh (Device removed)
	os.Remove(devPath) // Simulate device disappearance
	changed, err = cdp.refreshDevices()
	if err != nil {
		t.Fatalf("Third refresh failed: %v", err)
	}

	// The device is gone, so discovery returns empty list.
	// The refresh logic detects it's missing from the new list compared to old list.
	if len(cdp.ccDevices) != 0 {
		t.Errorf("Expected 0 devices after removal, got %d", len(cdp.ccDevices))
	}
}
