package models

import (
	"context"
	"strings"

	"github.com/google/uuid"
	ent "github.com/open-uem/ent"
	"github.com/open-uem/ent/selfservicepackage"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/partials"
)

func (m *Model) CreateSelfServicePackage(ctx context.Context, name, description, category, version string, pkgType selfservicepackage.PackageType, sourceType selfservicepackage.SourceType, sourceURL, filePath, checksum string, execContext selfservicepackage.ExecutionContext, silentArgs, icon string, enabled bool) (*ent.SelfServicePackage, error) {
	create := m.Client.SelfServicePackage.Create().
		SetName(name).
		SetPackageType(pkgType).
		SetSourceType(sourceType).
		SetExecutionContext(execContext).
		SetEnabled(enabled)

	if description != "" {
		create.SetDescription(description)
	}
	if category != "" {
		create.SetCategory(category)
	}
	if version != "" {
		create.SetVersion(version)
	}
	if sourceURL != "" {
		create.SetSourceURL(sourceURL)
	}
	if filePath != "" {
		create.SetFilePath(filePath)
	}
	if checksum != "" {
		create.SetChecksumSha256(checksum)
	}
	if silentArgs != "" {
		create.SetSilentArgs(silentArgs)
	}
	if icon != "" {
		create.SetIcon(icon)
	}

	return create.Save(ctx)
}

func (m *Model) UpdateSelfServicePackage(ctx context.Context, id uuid.UUID, name, description, category, version string, pkgType selfservicepackage.PackageType, sourceType selfservicepackage.SourceType, sourceURL, filePath, checksum string, execContext selfservicepackage.ExecutionContext, silentArgs, icon string, enabled bool) (*ent.SelfServicePackage, error) {
	update := m.Client.SelfServicePackage.UpdateOneID(id).
		SetName(name).
		SetPackageType(pkgType).
		SetSourceType(sourceType).
		SetExecutionContext(execContext).
		SetEnabled(enabled)

	if description != "" {
		update.SetDescription(description)
	} else {
		update.ClearDescription()
	}
	if category != "" {
		update.SetCategory(category)
	}
	if version != "" {
		update.SetVersion(version)
	} else {
		update.ClearVersion()
	}
	if sourceURL != "" {
		update.SetSourceURL(sourceURL)
	} else {
		update.ClearSourceURL()
	}
	if filePath != "" {
		update.SetFilePath(filePath)
	}
	if checksum != "" {
		update.SetChecksumSha256(checksum)
	}
	if silentArgs != "" {
		update.SetSilentArgs(silentArgs)
	} else {
		update.ClearSilentArgs()
	}
	if icon != "" {
		update.SetIcon(icon)
	} else {
		update.ClearIcon()
	}

	return update.Save(ctx)
}

func (m *Model) DeleteSelfServicePackage(ctx context.Context, id uuid.UUID) error {
	return m.Client.SelfServicePackage.DeleteOneID(id).Exec(ctx)
}

func (m *Model) GetSelfServicePackageByID(ctx context.Context, id uuid.UUID) (*ent.SelfServicePackage, error) {
	return m.Client.SelfServicePackage.Get(ctx, id)
}

func (m *Model) GetAllSelfServicePackages(ctx context.Context) ([]*ent.SelfServicePackage, error) {
	return m.Client.SelfServicePackage.Query().Order(ent.Asc(selfservicepackage.FieldName)).All(ctx)
}

func (m *Model) GetSelfServicePackagesByPage(ctx context.Context, p partials.PaginationAndSort, f filters.SelfServicePackageFilter) ([]*ent.SelfServicePackage, error) {
	query := m.Client.SelfServicePackage.Query()

	if f.Search != "" {
		query.Where(selfservicepackage.Or(
			selfservicepackage.NameContainsFold(f.Search),
			selfservicepackage.DescriptionContainsFold(f.Search),
			selfservicepackage.CategoryContainsFold(f.Search),
		))
	}
	if f.Category != "" {
		query.Where(selfservicepackage.CategoryEqualFold(f.Category))
	}
	if f.Type != "" {
		query.Where(selfservicepackage.PackageTypeEQ(selfservicepackage.PackageType(f.Type)))
	}
	if f.Enabled != "" {
		if strings.EqualFold(f.Enabled, "true") || strings.EqualFold(f.Enabled, "enabled") {
			query.Where(selfservicepackage.Enabled(true))
		} else if strings.EqualFold(f.Enabled, "false") || strings.EqualFold(f.Enabled, "disabled") {
			query.Where(selfservicepackage.Enabled(false))
		}
	}

	switch p.SortBy {
	case "name":
		if p.SortOrder == "desc" {
			query = query.Order(ent.Desc(selfservicepackage.FieldName))
		} else {
			query = query.Order(ent.Asc(selfservicepackage.FieldName))
		}
	case "category":
		if p.SortOrder == "desc" {
			query = query.Order(ent.Desc(selfservicepackage.FieldCategory))
		} else {
			query = query.Order(ent.Asc(selfservicepackage.FieldCategory))
		}
	case "version":
		if p.SortOrder == "desc" {
			query = query.Order(ent.Desc(selfservicepackage.FieldVersion))
		} else {
			query = query.Order(ent.Asc(selfservicepackage.FieldVersion))
		}
	case "type":
		if p.SortOrder == "desc" {
			query = query.Order(ent.Desc(selfservicepackage.FieldPackageType))
		} else {
			query = query.Order(ent.Asc(selfservicepackage.FieldPackageType))
		}
	default:
		query = query.Order(ent.Asc(selfservicepackage.FieldName))
	}

	if p.PageSize > 0 {
		query = query.Limit(p.PageSize).Offset((p.CurrentPage - 1) * p.PageSize)
	}

	return query.All(ctx)
}

func (m *Model) CountSelfServicePackages(ctx context.Context, f filters.SelfServicePackageFilter) (int, error) {
	query := m.Client.SelfServicePackage.Query()
	if f.Search != "" {
		query.Where(selfservicepackage.Or(
			selfservicepackage.NameContainsFold(f.Search),
			selfservicepackage.DescriptionContainsFold(f.Search),
			selfservicepackage.CategoryContainsFold(f.Search),
		))
	}
	if f.Category != "" {
		query.Where(selfservicepackage.CategoryEqualFold(f.Category))
	}
	if f.Type != "" {
		query.Where(selfservicepackage.PackageTypeEQ(selfservicepackage.PackageType(f.Type)))
	}
	if f.Enabled != "" {
		if strings.EqualFold(f.Enabled, "true") || strings.EqualFold(f.Enabled, "enabled") {
			query.Where(selfservicepackage.Enabled(true))
		} else if strings.EqualFold(f.Enabled, "false") || strings.EqualFold(f.Enabled, "disabled") {
			query.Where(selfservicepackage.Enabled(false))
		}
	}
	return query.Count(ctx)
}
