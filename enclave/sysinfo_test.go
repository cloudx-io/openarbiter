package enclave

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestReadMemInfo_UsesMemAvailable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := writeFile(t, dir, "meminfo", `MemTotal:       1024 kB
MemAvailable:    512 kB
Buffers:           0 kB
Cached:            0 kB
MemFree:           0 kB
`)
	mem, err := readMemInfo(path)
	require.NoError(t, err)
	assert.Equal(t, uint64(1024*1024), mem.totalBytes)
	assert.Equal(t, uint64(512*1024), mem.usedBytes)
	assert.InDelta(t, 50.0, mem.usagePercent, 0.001)
}

func TestReadMemInfo_FallsBackWithoutMemAvailable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := writeFile(t, dir, "meminfo", `MemTotal:       1000 kB
MemFree:         200 kB
Buffers:         100 kB
Cached:          100 kB
`)
	mem, err := readMemInfo(path)
	require.NoError(t, err)
	assert.Equal(t, uint64(1000*1024), mem.totalBytes)
	// available = 200+100+100 = 400, used = 600.
	assert.Equal(t, uint64(600*1024), mem.usedBytes)
}

func TestParseCPULine(t *testing.T) {
	t.Parallel()
	ticks, err := parseCPULine("cpu  100 50 30 1000 5 0 0 0")
	require.NoError(t, err)
	assert.Equal(t, uint64(100+50+30+1000+5), ticks.total)
	assert.Equal(t, uint64(1000), ticks.idle)
}

func TestSampleCPUUsage_Computes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := writeFile(t, dir, "stat", "cpu  10 0 0 90 0 0 0 0\n")
	// Override the file content between the two samples by rewriting it
	// inside a goroutine racing the cpuSampleInterval window.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = os.WriteFile(path, []byte("cpu  60 0 0 140 0 0 0 0\n"), 0o600)
	}()
	pct, err := sampleCPUUsage(path, cpuSampleInterval)
	<-done
	require.NoError(t, err)
	// total_delta = 200-100 = 100, idle_delta = 140-90 = 50, pct = 50.
	assert.InDelta(t, 50.0, pct, 0.01)
}

func TestGetSystemInfo_LiveProcfs(t *testing.T) {
	t.Parallel()
	info, err := GetSystemInfo()
	require.NoError(t, err)
	assert.Positive(t, info.MemTotalBytes)
	assert.Positive(t, info.NumCPUs)
}
