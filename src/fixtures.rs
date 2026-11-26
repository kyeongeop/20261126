use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult, ErrorCode};
use crate::inflate::MAX_INPUT_BYTES;
use crate::manifest::UploadManifest;
use crate::path::{confined_file, safe_join};

/// All runtime reads go through this store.  The repository root and fixture
/// root are canonicalized once; every requested file must remain below the
/// fixture root even after symlink resolution.
#[derive(Debug, Clone)]
pub struct FixtureStore {
    repo_root: PathBuf,
    fixture_root: PathBuf,
}

impl FixtureStore {
    pub fn new(repo_root: impl AsRef<Path>, fixture_dir: &str) -> AppResult<Self> {
        let repo_root = repo_root.as_ref().canonicalize().map_err(|error| {
            AppError::new(
                ErrorCode::FixtureRootNotFound,
                format!("cannot resolve repository root: {error}"),
            )
        })?;
        let requested = Path::new(fixture_dir);
        let fixture_join = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            safe_join(&repo_root, fixture_dir)?
        };
        let fixture_root = fixture_join.canonicalize().map_err(|error| {
            AppError::at_path(
                ErrorCode::FixtureRootNotFound,
                fixture_dir,
                format!("cannot resolve fixture root: {error}"),
            )
        })?;
        if !fixture_root.starts_with(&repo_root) {
            return Err(AppError::at_path(
                ErrorCode::PathOutsideFixtureRoot,
                fixture_dir,
                "fixture root resolves outside the repository",
            ));
        }
        if !fixture_root.is_dir() {
            return Err(AppError::at_path(
                ErrorCode::FixtureRootNotFound,
                fixture_dir,
                "fixture root is not a directory",
            ));
        }
        Ok(Self {
            repo_root,
            fixture_root,
        })
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn fixture_root(&self) -> &Path {
        &self.fixture_root
    }

    pub fn resolve(&self, relative: &str) -> AppResult<PathBuf> {
        let mut missing = None;
        for candidate in self.candidate_paths(relative) {
            match confined_file(&self.fixture_root, &candidate) {
                Ok(path) => return Ok(path),
                Err(error) if error.code == ErrorCode::ArchiveNotFound => missing = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(missing.unwrap_or_else(|| {
            AppError::at_path(
                ErrorCode::ArchiveNotFound,
                relative,
                "fixture file does not exist",
            )
        }))
    }

    pub fn read_bytes(&self, relative: &str) -> AppResult<Vec<u8>> {
        let path = self.resolve(relative)?;
        let metadata = fs::metadata(&path).map_err(|error| {
            AppError::at_path(
                ErrorCode::ArchiveReadFailed,
                relative,
                format!("cannot inspect fixture file: {error}"),
            )
        })?;
        if metadata.len() > MAX_INPUT_BYTES {
            return Err(AppError::at_path(
                ErrorCode::ArchiveReadFailed,
                relative,
                format!("archive exceeds the {} byte input limit", MAX_INPUT_BYTES),
            ));
        }
        fs::read(&path).map_err(|error| {
            AppError::at_path(
                ErrorCode::ArchiveReadFailed,
                relative,
                format!("cannot read fixture file: {error}"),
            )
        })
    }

    pub fn read_manifest(&self, relative: &str) -> AppResult<UploadManifest> {
        let mut missing = None;
        let mut path = None;
        for candidate in self.candidate_paths(relative) {
            let joined = if Path::new(&candidate).is_absolute() {
                PathBuf::from(&candidate)
            } else {
                safe_join(&self.fixture_root, &candidate)?
            };
            match joined.canonicalize() {
                Ok(canonical) if canonical.starts_with(&self.fixture_root) => {
                    path = Some(canonical);
                    break;
                }
                Ok(_) => {
                    return Err(AppError::at_path(
                        ErrorCode::PathOutsideFixtureRoot,
                        relative,
                        "manifest resolves outside the fixture root",
                    ))
                }
                Err(error) => missing = Some(error),
            }
        }
        let path = path.ok_or_else(|| {
            AppError::at_path(
                ErrorCode::ManifestNotFound,
                relative,
                format!(
                    "cannot open upload manifest: {}",
                    missing
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "file does not exist".to_string())
                ),
            )
        })?;
        let text = fs::read_to_string(&path).map_err(|error| {
            AppError::at_path(
                ErrorCode::ManifestReadFailed,
                relative,
                format!("cannot read upload manifest: {error}"),
            )
        })?;
        UploadManifest::from_json_str(&text).map_err(|mut error| {
            if error.details.is_object() {
                if let Some(object) = error.details.as_object_mut() {
                    object.insert("manifest".to_string(), relative.into());
                }
            }
            error
        })
    }

    /// List top-level JSON manifests in the fixture root.  Used by the CLI's
    /// `list` command and by tests; directory entries are not followed.
    pub fn list_manifests(&self) -> AppResult<Vec<String>> {
        let entries = fs::read_dir(&self.fixture_root).map_err(|error| {
            AppError::new(
                ErrorCode::FixtureRootNotFound,
                format!("cannot list fixture root: {error}"),
            )
        })?;
        let mut manifests = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                AppError::new(
                    ErrorCode::FixtureRootNotFound,
                    format!("cannot read fixture directory entry: {error}"),
                )
            })?;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    manifests.push(name.to_string());
                }
            }
        }
        manifests.sort();
        Ok(manifests)
    }

    fn candidate_paths(&self, relative: &str) -> Vec<String> {
        let mut candidates = vec![relative.to_string()];
        if let Some(name) = self.fixture_root.file_name().and_then(|name| name.to_str()) {
            let prefix = format!("{name}/");
            if let Some(stripped) = relative.strip_prefix(&prefix) {
                candidates.push(stripped.to_string());
            }
        }
        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_canonical_fixture_root() {
        let store =
            FixtureStore::new(env!("CARGO_MANIFEST_DIR"), "fixtures").expect("fixture store");
        assert!(store.fixture_root().ends_with("fixtures"));
        assert!(store.fixture_root().starts_with(store.repo_root()));
    }
}
