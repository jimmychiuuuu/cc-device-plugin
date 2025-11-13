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
	"github.com/prometheus/client_golang/prometheus" // ADD THIS IMPORT
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

// ==========================================
// Part 1: Globals
// ==========================================
const (
	testBuffer = 3 * time.Second
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowAll()) // Allow all for tests
	logger = log.With(logger, "timestamp", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)
}

// ==========================================
// Part 2: Test Helpers (Direct Construction)
// ==========================================

// constructTestPlugin creates a *CcDevicePlugin directly
func constructTestPlugin(t *testing.T, spec *CcDeviceSpec) *CcDevicePlugin {
	t.Helper()
	tmpDir := t.TempDir()

	// Create dummy device files based on the spec
	for idx, path := range spec.DevicePaths {
		absPath := filepath.Join(tmpDir, path)
		err := os.MkdirAll(filepath.Dir(absPath), 0755)
		if err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		f, err := os.Create(absPath)
		if err != nil {
			t.Fatalf("failed to create mock device: %v", err)
		}
		f.Close()
		// Update spec to use absolute path
		spec.DevicePaths[idx] = absPath
	}
	// Create dummy measurement files if needed
	for idx, path := range spec.MeasurementPaths {
		absPath := filepath.Join(tmpDir, path)
		err := os.MkdirAll(filepath.Dir(absPath), 0755)
		if err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		f, err := os.Create(absPath)
		if err != nil {
			t.Fatalf("failed to create mock measurement: %v", err)
		}
		f.WriteString("dummy_measurement_data")
		f.Close()
		// Update spec to use absolute path
		spec.MeasurementPaths[idx] = absPath
	}
	if spec.DeviceLimit == 0 {
		spec.DeviceLimit = 1 // Default limit for tests if not set
	}

	cdp := &CcDevicePlugin{
		cds:                        spec,
		ccDevices:                  make(map[string]CcDevice),
		logger:                     logger,
		copiedEventLogDirectory:    filepath.Join(tmpDir, "copied_measurements"),
		copiedEventLogLocation:     filepath.Join(tmpDir, "copied_measurements", "binary_bios_measurements"),
		containerEventLogDirectory: "/run/cc-device-plugin",
		// INITIALIZE METRICS HERE:
		deviceGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "test_cc_device_plugin_devices",
		}),
		allocationsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_cc_device_plugin_allocations_total",
		}),
	}
	os.MkdirAll(cdp.copiedEventLogDirectory, 0755)
	return cdp
}

func getExpectedID(resourceName string, limit int, index int) string {
	h := sha1.New()
	h.Write([]byte(resourceName))
	baseID := fmt.Sprintf("%x", h.Sum(nil))
	if limit > 1 {
		return fmt.Sprintf("%s-%d", baseID, index)
	}
	return baseID
}

// ==========================================
// Part 3: Test Cases
// ==========================================
func TestDiscoverTDX(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:         "intel.com/tdx",
		DevicePaths:      []string{"dev/tdx-guest"},
		MeasurementPaths: []string{},
		DeviceLimit:      1,
	}
	cdp := constructTestPlugin(t, spec)
	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("Expected 1 device, got %d", len(devices)) // Changed to Fatalf
	}
	if len(devices[0].Mounts) != 0 {
		t.Errorf("TDX should have 0 mounts, got %d", len(devices[0].Mounts))
	}
	if devices[0].DeviceSpecs[0].HostPath != spec.DevicePaths[0] {
		t.Errorf("HostPath mismatch. Got %s, Want %s", devices[0].DeviceSpecs[0].HostPath, spec.DevicePaths[0])
	}
	expectedID := getExpectedID(spec.Resource, spec.DeviceLimit, 0)
	if devices[0].ID != expectedID {
		t.Errorf("Device ID mismatch: got %s, want %s", devices[0].ID, expectedID)
	}
}

func TestDiscoverSEVSNP(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:         "amd.com/sev-snp",
		DevicePaths:      []string{"dev/sev-guest"},
		MeasurementPaths: []string{},
		DeviceLimit:      1,
	}
	cdp := constructTestPlugin(t, spec)
	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("Expected 1 device, got %d", len(devices))
	}
	if len(devices[0].Mounts) != 0 {
		t.Errorf("SEV-SNP should have 0 mounts, got %d", len(devices[0].Mounts))
	}
	if devices[0].DeviceSpecs[0].HostPath != spec.DevicePaths[0] {
		t.Errorf("HostPath mismatch. Got %s, Want %s", devices[0].DeviceSpecs[0].HostPath, spec.DevicePaths[0])
	}
	expectedID := getExpectedID(spec.Resource, spec.DeviceLimit, 0)
	if devices[0].ID != expectedID {
		t.Errorf("Device ID mismatch: got %s, want %s", devices[0].ID, expectedID)
	}
}

func TestDiscoverTPM(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:         "google.com/cc",
		DevicePaths:      []string{"dev/tpmrm0"},
		MeasurementPaths: []string{"sys/binary_bios_measurements"},
		DeviceLimit:      3, // Test with a limit > 1
	}
	cdp := constructTestPlugin(t, spec)
	devices, err := cdp.discoverCcDevices()
	if err != nil {
		t.Fatalf("discoverCcDevices failed: %v", err)
	}

	if len(devices) != spec.DeviceLimit {
		t.Fatalf("Expected %d devices, got %d", spec.DeviceLimit, len(devices))
	}

	for i, device := range devices {
		if len(device.Mounts) == 0 {
			t.Errorf("TPM device index %d should have mounts, got 0", i)
		} else {
			// Check if measurement file was copied
			if _, err := os.Stat(cdp.copiedEventLogLocation); err != nil {
				t.Errorf("Measurement file not copied: %v", err)
			}
		}
		if len(device.DeviceSpecs) == 0 {
			t.Errorf("TPM device index %d should have DeviceSpecs", i)
			continue
		}
		if device.DeviceSpecs[0].HostPath != spec.DevicePaths[0] {
			t.Errorf("HostPath mismatch index %d. Got %s, Want %s", i, device.DeviceSpecs[0].HostPath, spec.DevicePaths[0])
		}
		expectedID := getExpectedID(spec.Resource, spec.DeviceLimit, i)
		if device.ID != expectedID {
			t.Errorf("Device ID mismatch index %d: got %s, want %s", i, device.ID, expectedID)
		}
	}
}

func TestAllocate(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:    "amd.com/sev-snp",
		DevicePaths: []string{"dev/sev-guest"},
		DeviceLimit: 1,
	}
	cdp := constructTestPlugin(t, spec)
	_, err := cdp.refreshDevices() // Call refreshDevices to populate cdp.ccDevices
	if err != nil {
		t.Fatalf("refreshDevices failed: %v", err)
	}
	expectedID := getExpectedID(spec.Resource, spec.DeviceLimit, 0)

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
		t.Fatalf("Expected 1 container response, got %d", len(resp.ContainerResponses))
	}
	if len(resp.ContainerResponses[0].Devices) == 0 {
		t.Fatalf("Expected > 0 devices in response, got 0")
	}
	if resp.ContainerResponses[0].Devices[0].HostPath != spec.DevicePaths[0] {
		t.Errorf("Allocation HostPath mismatch. Got %s, Want %s", resp.ContainerResponses[0].Devices[0].HostPath, spec.DevicePaths[0])
	}
}

// ... Keep other tests like TestAllocateNotExistDevice, TestRefreshDevices, TestListAndWatch
// Remember to update spec.DevicePaths indices if more paths are added in a test.

func TestRefreshDevices(t *testing.T) {
	spec := &CcDeviceSpec{
		Resource:    "intel.com/tdx",
		DevicePaths: []string{"dev/tdx-guest"},
		DeviceLimit: 1,
	}
	cdp := constructTestPlugin(t, spec)
	devPath := spec.DevicePaths[0] // Absolute path from constructTestPlugin

	// 1. First Refresh (Device exists)
	changed, err := cdp.refreshDevices()
	if err != nil {
		t.Fatalf("First refresh failed: %v", err)
	}
	if changed { // should be false, means devices changed from empty
		t.Errorf("Expected changed=false on first refresh, got true")
	}
	if len(cdp.ccDevices) != 1 {
		t.Errorf("Expected 1 device in map, got %d", len(cdp.ccDevices))
	}

	// 2. Second Refresh (No change)
	changed, err = cdp.refreshDevices()
	if err != nil {
		t.Fatalf("Second refresh failed: %v", err)
	}
	if !changed { // should be true, means devices are the same
		t.Errorf("Expected changed=true (unchanged), got false")
	}

	// 3. Third Refresh (Device removed)
	if err := os.Remove(devPath); err != nil {
		t.Fatalf("Failed to remove device path: %v", err)
	}
	changed, err = cdp.refreshDevices()
	if err != nil {
		t.Fatalf("Third refresh failed: %v", err)
	}
	if changed { // should be false, means devices changed
		t.Errorf("Expected changed=false after removal, got true")
	}
	if len(cdp.ccDevices) != 0 {
		t.Errorf("Expected 0 devices after removal, got %d", len(cdp.ccDevices))
	}
}

// NOTE: You'll need to add TestAllocateNotExistDevice and TestListAndWatch back if they were removed.
// They should function with the above changes.
