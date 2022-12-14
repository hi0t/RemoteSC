package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testAddress    = "127.0.0.1:44555"
	testLib        = "/usr/lib/softhsm/libsofthsm2.so"
	testSoftHSMCfg = `
log.level = INFO
objectstore.backend = file
directories.tokendir = {tokendir}
	`
)

type pkcs11TestSuite struct {
	suite.Suite
	suite.SetupAllSuite
	suite.TearDownAllSuite
	tmp string
	ctx *pkcs11_ctx
}

func (s *pkcs11TestSuite) SetupSuite() {
	libPath, err := buildRPKS11()
	require.NoError(s.T(), err)

	s.tmp, err = prepareSoftHSMCfg()
	require.NoError(s.T(), err)

	Start(Config{
		Provider: testLib,
		Address:  testAddress,
	})

	s.ctx, err = OpenPKCS11(libPath)
	require.NoError(s.T(), err)

	require.NoError(s.T(), s.ctx.Initialize())
}

func (s *pkcs11TestSuite) TearDownSuite() {
	s.NoError(s.ctx.Finalize())
	s.ctx.Close()
	Stop()
	os.RemoveAll(s.tmp)
}

func (s *pkcs11TestSuite) TestGetInfo() {
	info, err := s.ctx.GetInfo()
	s.NoError(err)

	s.Equal("SoftHSM", info.ManufacturerID)
	s.Equal("Implementation of PKCS11", info.LibraryDescription)
}

func TestPkcs11ApiTestSuite(t *testing.T) {
	suite.Run(t, new(pkcs11TestSuite))
}

func buildRPKS11() (string, error) {
	wd, _ := os.Getwd()
	wd = filepath.Join(wd, "..")
	srcDir := filepath.Join(wd, "rpkcs11")
	buildDir := filepath.Join(wd, "build")

	cmd := exec.Command("/usr/bin/cmake",
		"-DCMAKE_BUILD_TYPE=Debug",
		"-S"+srcDir,
		"-B"+buildDir,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}

	cmd = exec.Command("/usr/bin/cmake", "--build", buildDir)
	if err := cmd.Run(); err != nil {
		return "", err
	}

	return filepath.Join(buildDir, "librpkcs11.so"), nil
}

func prepareSoftHSMCfg() (string, error) {
	tmp, err := os.MkdirTemp("", "pkcs11")
	if err != nil {
		return "", err
	}

	cfgPaht := filepath.Join(tmp, "softhsm2.conf")
	cfg := strings.Replace(testSoftHSMCfg, "{tokendir}", tmp, 1)
	if err := os.WriteFile(cfgPaht, []byte(cfg), 0644); err != nil {
		return tmp, err
	}

	os.Setenv("SOFTHSM2_CONF", cfgPaht)
	return tmp, nil
}
