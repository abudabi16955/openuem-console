package packages_views

import (
	"testing"

	ent "github.com/open-uem/ent"
	"github.com/open-uem/ent/selfservicepackage"
	"github.com/stretchr/testify/assert"
)

func TestGetPackagePlatform(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *ent.SelfServicePackage
		expected string
	}{
		{
			name: "MSI package with mac in name is still Windows",
			pkg: &ent.SelfServicePackage{
				Name:        "Macrium Reflect",
				Description: "Backup utility",
				PackageType: selfservicepackage.PackageTypeMsi,
			},
			expected: "Windows",
		},
		{
			name: "EXE package with machine in description is Windows",
			pkg: &ent.SelfServicePackage{
				Name:        "Virtual Machine Manager",
				Description: "Manage machines",
				PackageType: selfservicepackage.PackageTypeExe,
			},
			expected: "Windows",
		},
		{
			name: "Winget package with macro in name is Windows",
			pkg: &ent.SelfServicePackage{
				Name:        "Macro Recorder",
				PackageType: selfservicepackage.PackageTypeWinget,
			},
			expected: "Windows",
		},
		{
			name: "ZIP package containing macos is macOS",
			pkg: &ent.SelfServicePackage{
				Name:        "Editor for macOS",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "macOS",
		},
		{
			name: "ZIP package containing darwin is macOS",
			pkg: &ent.SelfServicePackage{
				Name:        "Darwin CLI Tool",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "macOS",
		},
		{
			name: "ZIP package containing osx is macOS",
			pkg: &ent.SelfServicePackage{
				Name:        "OSX Terminal Helper",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "macOS",
		},
		{
			name: "ZIP package containing mac os is macOS",
			pkg: &ent.SelfServicePackage{
				Name:        "Mac OS Utility",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "macOS",
		},
		{
			name: "ZIP package containing machine is not macOS",
			pkg: &ent.SelfServicePackage{
				Name:        "Machine Setup Script",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "Windows",
		},
		{
			name: "ZIP package for Ubuntu is Linux",
			pkg: &ent.SelfServicePackage{
				Name:        "Ubuntu Package",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "Linux",
		},
		{
			name: "ZIP package for Debian is Linux",
			pkg: &ent.SelfServicePackage{
				Name:        "Debian Service Installer",
				PackageType: selfservicepackage.PackageTypeZip,
			},
			expected: "Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPackagePlatform(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
