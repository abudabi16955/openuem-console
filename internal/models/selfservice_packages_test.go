package models

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/open-uem/ent/enttest"
	"github.com/open-uem/ent/selfservicepackage"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfServicePackages_CRUD(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	model := Model{Client: client}
	ctx := context.Background()

	// 1. Create packages
	pkg1, err := model.CreateSelfServicePackage(
		ctx,
		"Mozilla Firefox",
		"Popular open-source web browser",
		"Browsers",
		"124.0",
		selfservicepackage.PackageTypeMsi,
		selfservicepackage.SourceTypeUpload,
		"",
		"/var/packages/firefox.msi",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		selfservicepackage.ExecutionContextSystem,
		"/qn /norestart",
		"globe",
		true,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, pkg1.ID)
	assert.Equal(t, "Mozilla Firefox", pkg1.Name)
	assert.Equal(t, "Browsers", pkg1.Category)
	assert.True(t, pkg1.Enabled)

	pkg2, err := model.CreateSelfServicePackage(
		ctx,
		"Visual Studio Code",
		"Code editing redefined",
		"Development",
		"1.88.0",
		selfservicepackage.PackageTypeWinget,
		selfservicepackage.SourceTypeHTTPS,
		"Microsoft.VisualStudioCode",
		"",
		"",
		selfservicepackage.ExecutionContextUser,
		"--silent",
		"code",
		false,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, pkg2.ID)
	assert.Equal(t, "Visual Studio Code", pkg2.Name)
	assert.False(t, pkg2.Enabled)

	// 2. Get by ID
	fetched, err := model.GetSelfServicePackageByID(ctx, pkg1.ID)
	require.NoError(t, err)
	assert.Equal(t, pkg1.ID, fetched.ID)
	assert.Equal(t, "Mozilla Firefox", fetched.Name)

	// Non-existent ID
	_, err = model.GetSelfServicePackageByID(ctx, uuid.New())
	assert.Error(t, err)

	// 3. GetAll
	all, err := model.GetAllSelfServicePackages(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	// 4. Count and Pagination with filters
	count, err := model.CountSelfServicePackages(ctx, filters.SelfServicePackageFilter{})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Filter by search
	countFiltered, err := model.CountSelfServicePackages(ctx, filters.SelfServicePackageFilter{Search: "Firefox"})
	require.NoError(t, err)
	assert.Equal(t, 1, countFiltered)

	// Filter by category
	countCategory, err := model.CountSelfServicePackages(ctx, filters.SelfServicePackageFilter{Category: "Development"})
	require.NoError(t, err)
	assert.Equal(t, 1, countCategory)

	// Filter by enabled
	countEnabled, err := model.CountSelfServicePackages(ctx, filters.SelfServicePackageFilter{Enabled: "true"})
	require.NoError(t, err)
	assert.Equal(t, 1, countEnabled)

	// Get by page
	p := partials.NewPaginationAndSort(10)
	p.CurrentPage = 1
	p.PageSize = 10
	pageItems, err := model.GetSelfServicePackagesByPage(ctx, p, filters.SelfServicePackageFilter{})
	require.NoError(t, err)
	assert.Len(t, pageItems, 2)

	// 5. Update package
	updated, err := model.UpdateSelfServicePackage(
		ctx,
		pkg1.ID,
		"Firefox Enterprise",
		"Updated description",
		"Browsers",
		"125.0",
		selfservicepackage.PackageTypeMsi,
		selfservicepackage.SourceTypeUpload,
		"",
		"/var/packages/firefox_new.msi",
		"abcdef1234567890",
		selfservicepackage.ExecutionContextSystem,
		"/quiet",
		"firefox-icon",
		true,
	)
	require.NoError(t, err)
	assert.Equal(t, "Firefox Enterprise", updated.Name)
	assert.Equal(t, "125.0", updated.Version)
	assert.Equal(t, "abcdef1234567890", updated.ChecksumSha256)

	// 6. Delete package
	err = model.DeleteSelfServicePackage(ctx, pkg2.ID)
	require.NoError(t, err)

	remaining, err := model.GetAllSelfServicePackages(ctx)
	require.NoError(t, err)
	assert.Len(t, remaining, 1)
	assert.Equal(t, pkg1.ID, remaining[0].ID)
}
