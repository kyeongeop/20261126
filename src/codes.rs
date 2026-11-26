use serde_json::{json, Value};

/// A structural finding tied to one archive member (or to the archive itself
/// for archive-level comparisons).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueCode {
    AbsolutePath,
    PathTraversal,
    NulInPath,
    PathSeparatorAmbiguity,
    SymlinkAbsoluteTarget,
    SymlinkTargetTraversal,
    SymlinkDangling,
    SymlinkLoop,
    DuplicatePath,
    DuplicatePathCaseInsensitive,
    HardLinkAbsoluteTarget,
    HardLinkTargetTraversal,
    HardLinkTargetMissing,
    PathPrefixConflict,
    PermissionSetuid,
    PermissionSetgid,
    PermissionSticky,
    PermissionWorldWritable,
    PermissionGroupWritable,
    PermissionMissingOwnerRead,
    PermissionDirectoryNotSearchable,
    PermissionExecMissingForBinary,
    PermissionExecOnNonBinary,
    PermissionModeInvalid,
    SpecialFile,
    EncryptedMember,
    NonUtf8Path,
    MemberContentError,
    CrcMismatch,
    BinaryParseFailed,
    EmptyMemberName,
    ArchiveHashMismatch,
    ReuploadMemberAdded,
    ReuploadMemberRemoved,
    ReuploadTypeChanged,
    ReuploadModeChanged,
    ReuploadSymlinkTargetChanged,
    ReuploadContentChanged,
    ReuploadNewIssue,
    ReuploadIssueRemains,
    ReuploadIssueFixed,
}

impl IssueCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AbsolutePath => "ARC2001",
            Self::PathTraversal => "ARC2002",
            Self::NulInPath => "ARC2003",
            Self::PathSeparatorAmbiguity => "ARC2004",
            Self::SymlinkAbsoluteTarget => "ARC2005",
            Self::SymlinkTargetTraversal => "ARC2006",
            Self::SymlinkDangling => "ARC2007",
            Self::SymlinkLoop => "ARC2008",
            Self::DuplicatePath => "ARC2009",
            Self::DuplicatePathCaseInsensitive => "ARC2010",
            Self::HardLinkAbsoluteTarget => "ARC2011",
            Self::HardLinkTargetTraversal => "ARC2012",
            Self::HardLinkTargetMissing => "ARC2013",
            Self::PathPrefixConflict => "ARC2014",
            Self::PermissionSetuid => "ARC2015",
            Self::PermissionSetgid => "ARC2016",
            Self::PermissionSticky => "ARC2017",
            Self::PermissionWorldWritable => "ARC2018",
            Self::PermissionGroupWritable => "ARC2019",
            Self::PermissionMissingOwnerRead => "ARC2020",
            Self::PermissionDirectoryNotSearchable => "ARC2021",
            Self::PermissionExecMissingForBinary => "ARC2022",
            Self::PermissionExecOnNonBinary => "ARC2023",
            Self::PermissionModeInvalid => "ARC2024",
            Self::SpecialFile => "ARC2025",
            Self::EncryptedMember => "ARC2026",
            Self::NonUtf8Path => "ARC2027",
            Self::MemberContentError => "ARC2028",
            Self::CrcMismatch => "ARC2029",
            Self::BinaryParseFailed => "ARC2030",
            Self::EmptyMemberName => "ARC2031",
            Self::ArchiveHashMismatch => "ARC2032",
            Self::ReuploadMemberAdded => "ARC3001",
            Self::ReuploadMemberRemoved => "ARC3002",
            Self::ReuploadTypeChanged => "ARC3003",
            Self::ReuploadModeChanged => "ARC3004",
            Self::ReuploadSymlinkTargetChanged => "ARC3005",
            Self::ReuploadContentChanged => "ARC3006",
            Self::ReuploadNewIssue => "ARC3007",
            Self::ReuploadIssueRemains => "ARC3008",
            Self::ReuploadIssueFixed => "ARC3009",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::AbsolutePath => "ABSOLUTE_PATH",
            Self::PathTraversal => "PATH_TRAVERSAL",
            Self::NulInPath => "NUL_IN_PATH",
            Self::PathSeparatorAmbiguity => "PATH_SEPARATOR_AMBIGUITY",
            Self::SymlinkAbsoluteTarget => "SYMLINK_ABSOLUTE_TARGET",
            Self::SymlinkTargetTraversal => "SYMLINK_TARGET_TRAVERSAL",
            Self::SymlinkDangling => "SYMLINK_DANGLING",
            Self::SymlinkLoop => "SYMLINK_LOOP",
            Self::DuplicatePath => "DUPLICATE_PATH",
            Self::DuplicatePathCaseInsensitive => "DUPLICATE_PATH_CASE_INSENSITIVE",
            Self::HardLinkAbsoluteTarget => "HARD_LINK_ABSOLUTE_TARGET",
            Self::HardLinkTargetTraversal => "HARD_LINK_TARGET_TRAVERSAL",
            Self::HardLinkTargetMissing => "HARD_LINK_TARGET_MISSING",
            Self::PathPrefixConflict => "PATH_PREFIX_CONFLICT",
            Self::PermissionSetuid => "PERMISSION_SETUID",
            Self::PermissionSetgid => "PERMISSION_SETGID",
            Self::PermissionSticky => "PERMISSION_STICKY",
            Self::PermissionWorldWritable => "PERMISSION_WORLD_WRITABLE",
            Self::PermissionGroupWritable => "PERMISSION_GROUP_WRITABLE",
            Self::PermissionMissingOwnerRead => "PERMISSION_MISSING_OWNER_READ",
            Self::PermissionDirectoryNotSearchable => "PERMISSION_DIRECTORY_NOT_SEARCHABLE",
            Self::PermissionExecMissingForBinary => "PERMISSION_EXEC_MISSING_FOR_BINARY",
            Self::PermissionExecOnNonBinary => "PERMISSION_EXEC_ON_NON_BINARY",
            Self::PermissionModeInvalid => "PERMISSION_MODE_INVALID",
            Self::SpecialFile => "SPECIAL_FILE",
            Self::EncryptedMember => "ENCRYPTED_MEMBER",
            Self::NonUtf8Path => "NON_UTF8_PATH",
            Self::MemberContentError => "MEMBER_CONTENT_ERROR",
            Self::CrcMismatch => "CRC_MISMATCH",
            Self::BinaryParseFailed => "BINARY_PARSE_FAILED",
            Self::EmptyMemberName => "EMPTY_MEMBER_NAME",
            Self::ArchiveHashMismatch => "ARCHIVE_HASH_MISMATCH",
            Self::ReuploadMemberAdded => "REUPLOAD_MEMBER_ADDED",
            Self::ReuploadMemberRemoved => "REUPLOAD_MEMBER_REMOVED",
            Self::ReuploadTypeChanged => "REUPLOAD_TYPE_CHANGED",
            Self::ReuploadModeChanged => "REUPLOAD_MODE_CHANGED",
            Self::ReuploadSymlinkTargetChanged => "REUPLOAD_SYMLINK_TARGET_CHANGED",
            Self::ReuploadContentChanged => "REUPLOAD_CONTENT_CHANGED",
            Self::ReuploadNewIssue => "REUPLOAD_NEW_ISSUE",
            Self::ReuploadIssueRemains => "REUPLOAD_ISSUE_REMAINS",
            Self::ReuploadIssueFixed => "REUPLOAD_ISSUE_FIXED",
        }
    }

    pub const fn severity(self) -> Severity {
        match self {
            Self::AbsolutePath
            | Self::PathTraversal
            | Self::NulInPath
            | Self::SymlinkAbsoluteTarget
            | Self::SymlinkTargetTraversal
            | Self::SymlinkLoop
            | Self::DuplicatePath
            | Self::HardLinkAbsoluteTarget
            | Self::HardLinkTargetTraversal
            | Self::PathPrefixConflict
            | Self::PermissionSetuid
            | Self::PermissionSetgid
            | Self::PermissionWorldWritable
            | Self::PermissionModeInvalid
            | Self::SpecialFile
            | Self::EncryptedMember
            | Self::EmptyMemberName
            | Self::ArchiveHashMismatch
            | Self::ReuploadMemberRemoved
            | Self::ReuploadTypeChanged
            | Self::ReuploadNewIssue => Severity::Blocking,

            Self::PathSeparatorAmbiguity
            | Self::SymlinkDangling
            | Self::DuplicatePathCaseInsensitive
            | Self::HardLinkTargetMissing
            | Self::PermissionSticky
            | Self::PermissionGroupWritable
            | Self::PermissionMissingOwnerRead
            | Self::PermissionDirectoryNotSearchable
            | Self::PermissionExecMissingForBinary
            | Self::PermissionExecOnNonBinary
            | Self::NonUtf8Path
            | Self::MemberContentError
            | Self::CrcMismatch
            | Self::BinaryParseFailed
            | Self::ReuploadMemberAdded
            | Self::ReuploadModeChanged
            | Self::ReuploadSymlinkTargetChanged
            | Self::ReuploadIssueRemains => Severity::Warning,

            Self::ReuploadContentChanged | Self::ReuploadIssueFixed => Severity::Info,
        }
    }

    pub const fn title_zh(self) -> &'static str {
        match self {
            Self::AbsolutePath => "成员路径为绝对路径",
            Self::PathTraversal => "成员路径包含目录穿越",
            Self::NulInPath => "成员路径包含 NUL 字节",
            Self::PathSeparatorAmbiguity => "成员路径混用反斜杠分隔符",
            Self::SymlinkAbsoluteTarget => "符号链接指向绝对路径",
            Self::SymlinkTargetTraversal => "符号链接目标逃逸压缩包根",
            Self::SymlinkDangling => "符号链接目标不存在",
            Self::SymlinkLoop => "符号链接形成循环",
            Self::DuplicatePath => "压缩包内存在重复路径",
            Self::DuplicatePathCaseInsensitive => "路径仅大小写不同",
            Self::HardLinkAbsoluteTarget => "硬链接指向绝对路径",
            Self::HardLinkTargetTraversal => "硬链接目标逃逸压缩包根",
            Self::HardLinkTargetMissing => "硬链接目标不存在",
            Self::PathPrefixConflict => "文件与目录前缀冲突",
            Self::PermissionSetuid => "权限包含 setuid 位",
            Self::PermissionSetgid => "权限包含 setgid 位",
            Self::PermissionSticky => "权限包含 sticky 位",
            Self::PermissionWorldWritable => "权限允许所有用户写入",
            Self::PermissionGroupWritable => "权限允许同组用户写入",
            Self::PermissionMissingOwnerRead => "权限缺少所有者读取位",
            Self::PermissionDirectoryNotSearchable => "目录权限缺少可搜索位",
            Self::PermissionExecMissingForBinary => "可执行二进制缺少执行位",
            Self::PermissionExecOnNonBinary => "非二进制成员带执行位",
            Self::PermissionModeInvalid => "权限位异常或超出文件类型范围",
            Self::SpecialFile => "包含设备、FIFO 等特殊文件",
            Self::EncryptedMember => "成员已加密，无法检查内容",
            Self::NonUtf8Path => "成员路径不是合法 UTF-8",
            Self::MemberContentError => "成员内容读取或解压失败",
            Self::CrcMismatch => "成员 CRC 校验失败",
            Self::BinaryParseFailed => "二进制扩展名成员无法由 object 解析",
            Self::EmptyMemberName => "成员名称为空",
            Self::ArchiveHashMismatch => "外层压缩包 SHA-256 与声明不一致",
            Self::ReuploadMemberAdded => "修复包新增了上版不存在的成员",
            Self::ReuploadMemberRemoved => "修复包删除了上版存在的成员",
            Self::ReuploadTypeChanged => "修复包改变了成员类型",
            Self::ReuploadModeChanged => "修复包改变了成员权限",
            Self::ReuploadSymlinkTargetChanged => "修复包改变了符号链接目标",
            Self::ReuploadContentChanged => "修复包成员内容与上版不同",
            Self::ReuploadNewIssue => "修复包引入了新的结构问题",
            Self::ReuploadIssueRemains => "上版结构问题在修复包中仍然存在",
            Self::ReuploadIssueFixed => "上版结构问题已在修复包中解决",
        }
    }
}

/// Finding severity.  Only `Blocking` prevents a release upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Blocking,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Blocking => "blocking",
        }
    }

    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Info => "提示",
            Self::Warning => "警告",
            Self::Blocking => "阻断",
        }
    }
}

/// Stable catalog embedded in reports so downstream tools can display labels
/// without shipping a second copy of the code list.
pub fn issue_catalog() -> Value {
    let codes = [
        IssueCode::AbsolutePath,
        IssueCode::PathTraversal,
        IssueCode::NulInPath,
        IssueCode::PathSeparatorAmbiguity,
        IssueCode::SymlinkAbsoluteTarget,
        IssueCode::SymlinkTargetTraversal,
        IssueCode::SymlinkDangling,
        IssueCode::SymlinkLoop,
        IssueCode::DuplicatePath,
        IssueCode::DuplicatePathCaseInsensitive,
        IssueCode::HardLinkAbsoluteTarget,
        IssueCode::HardLinkTargetTraversal,
        IssueCode::HardLinkTargetMissing,
        IssueCode::PathPrefixConflict,
        IssueCode::PermissionSetuid,
        IssueCode::PermissionSetgid,
        IssueCode::PermissionSticky,
        IssueCode::PermissionWorldWritable,
        IssueCode::PermissionGroupWritable,
        IssueCode::PermissionMissingOwnerRead,
        IssueCode::PermissionDirectoryNotSearchable,
        IssueCode::PermissionExecMissingForBinary,
        IssueCode::PermissionExecOnNonBinary,
        IssueCode::PermissionModeInvalid,
        IssueCode::SpecialFile,
        IssueCode::EncryptedMember,
        IssueCode::NonUtf8Path,
        IssueCode::MemberContentError,
        IssueCode::CrcMismatch,
        IssueCode::BinaryParseFailed,
        IssueCode::EmptyMemberName,
        IssueCode::ArchiveHashMismatch,
        IssueCode::ReuploadMemberAdded,
        IssueCode::ReuploadMemberRemoved,
        IssueCode::ReuploadTypeChanged,
        IssueCode::ReuploadModeChanged,
        IssueCode::ReuploadSymlinkTargetChanged,
        IssueCode::ReuploadContentChanged,
        IssueCode::ReuploadNewIssue,
        IssueCode::ReuploadIssueRemains,
        IssueCode::ReuploadIssueFixed,
    ];
    Value::Array(
        codes
            .iter()
            .map(|code| {
                json!({
                    "code": code.as_str(),
                    "name": code.name(),
                    "severity": code.severity().as_str(),
                    "title_zh": code.title_zh(),
                })
            })
            .collect(),
    )
}
