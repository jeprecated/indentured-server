use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("cwd must be an absolute path")]
    CwdNotAbsolute,

    #[error("{field} must be a relative path")]
    PathNotRelative { field: String },

    #[error("{field} must not contain parent directory references")]
    PathHasParent { field: String },

    #[error("{field} must not be empty")]
    EmptyValue { field: String },

    #[error("cwd {cwd:?} is outside allowed root {root:?}")]
    CwdOutsideRoot { cwd: PathBuf, root: PathBuf },

    #[error("invalid path for {flag}: {source}")]
    InvalidPath {
        flag: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn validate_relative_path(raw: &str, field: &str) -> Result<PathBuf, ValidationError> {
    if raw.trim().is_empty() {
        return Err(ValidationError::EmptyValue {
            field: field.to_string(),
        });
    }

    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(ValidationError::PathNotRelative {
            field: field.to_string(),
        });
    }

    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(ValidationError::PathHasParent {
                field: field.to_string(),
            });
        }
    }

    Ok(path.to_path_buf())
}

pub fn validate_relative_pattern(pattern: &str, field: &str) -> Result<(), ValidationError> {
    if pattern.trim().is_empty() {
        return Err(ValidationError::EmptyValue {
            field: field.to_string(),
        });
    }

    let path = Path::new(pattern);
    if path.is_absolute() {
        return Err(ValidationError::PathNotRelative {
            field: field.to_string(),
        });
    }

    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(ValidationError::PathHasParent {
                field: field.to_string(),
            });
        }
    }

    Ok(())
}

pub fn validate_cwd(cwd: &Path, allowed_root: &Path) -> Result<PathBuf, ValidationError> {
    if !cwd.is_absolute() {
        return Err(ValidationError::CwdNotAbsolute);
    }

    let root =
        std::fs::canonicalize(allowed_root).map_err(|source| ValidationError::InvalidPath {
            flag: "allowed_root".to_string(),
            source,
        })?;
    let canonical_cwd =
        std::fs::canonicalize(cwd).map_err(|source| ValidationError::InvalidPath {
            flag: "cwd".to_string(),
            source,
        })?;

    if !canonical_cwd.starts_with(&root) {
        return Err(ValidationError::CwdOutsideRoot {
            cwd: canonical_cwd,
            root,
        });
    }

    Ok(canonical_cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn validate_cwd_under_root() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("home");
        let workspace = root.join("alice").join("workspace");
        let project = workspace.join("project");
        std::fs::create_dir_all(&project).expect("mkdir");

        let cwd = validate_cwd(&project, &workspace).expect("valid cwd");
        assert!(cwd.starts_with(&workspace));
    }

    #[test]
    fn validate_relative_path_rejects_absolute() {
        let err = validate_relative_path("/tmp", "cwd").unwrap_err();
        assert!(matches!(err, ValidationError::PathNotRelative { .. }));
    }

    #[test]
    fn validate_relative_path_rejects_parent() {
        let err = validate_relative_path("../tmp", "cwd").unwrap_err();
        assert!(matches!(err, ValidationError::PathHasParent { .. }));
    }
}
