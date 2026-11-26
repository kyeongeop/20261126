package main

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const maxUploadBytes int64 = 128 << 20

var (
	errArtifactMissing = errors.New("package archive is required")
	errUploadTooLarge  = errors.New("upload exceeds the size limit")
	errMalformedUpload = errors.New("malformed upload request")
	errFieldMismatch   = errors.New("path and form identity fields disagree")
	errRepairBase      = errors.New("repair target version is required")
)

type uploadInput struct {
	Name       string
	Version    string
	NewVersion string
	RepairOf   string
	Reason     string
	Reader     io.Reader
	cleanup    func()
}

func (in *uploadInput) Close() {
	if in.cleanup != nil {
		in.cleanup()
	}
}

func readUpload(w http.ResponseWriter, r *http.Request) (uploadInput, error) {
	if r.ContentLength > maxUploadBytes {
		return uploadInput{}, errUploadTooLarge
	}
	limitErr := func(err error) error {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errUploadTooLarge
		}
		return err
	}

	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "multipart/form-data" {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			if errors.Is(err, http.ErrNotMultipart) {
				return uploadInput{}, fmt.Errorf("%w: %v", errMalformedUpload, err)
			}
			limitError := limitErr(err)
			if errors.Is(limitError, errUploadTooLarge) {
				return uploadInput{}, limitError
			}
			return uploadInput{}, fmt.Errorf("%w: %v", errMalformedUpload, err)
		}
		input := uploadInput{
			Name:       firstValue(r, "name", "package_name", "pkg_name"),
			Version:    firstValue(r, "version", "package_version"),
			NewVersion: firstValue(r, "new_version", "newVersion"),
			RepairOf:   firstValue(r, "repair_of", "replaces", "replaces_version", "base_version"),
			Reason:     firstValue(r, "reason", "repair_reason"),
		}
		var file io.ReadCloser
		for _, field := range []string{"package", "artifact", "file", "tar", "archive"} {
			f, _, err := r.FormFile(field)
			if err == nil {
				file = f
				break
			}
			if !errors.Is(err, http.ErrMissingFile) {
				if r.MultipartForm != nil {
					_ = r.MultipartForm.RemoveAll()
				}
				return uploadInput{}, fmt.Errorf("%w: %v", errMalformedUpload, err)
			}
		}
		if file == nil {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
			return uploadInput{}, errArtifactMissing
		}
		input.Reader = file
		input.cleanup = func() {
			_ = file.Close()
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}
		return input, nil
	}

	if r.ContentLength == 0 {
		return uploadInput{}, errArtifactMissing
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	input := uploadInput{
		Name:       firstValue(r, "name", "package_name", "pkg_name"),
		Version:    firstValue(r, "version", "package_version"),
		NewVersion: firstValue(r, "new_version", "newVersion"),
		RepairOf:   firstValue(r, "repair_of", "replaces", "base_version"),
		Reason:     firstValue(r, "reason", "repair_reason"),
		Reader:     r.Body,
	}
	if input.Name == "" {
		input.Name = strings.TrimSpace(r.Header.Get("X-Package-Name"))
	}
	if input.Version == "" {
		input.Version = strings.TrimSpace(r.Header.Get("X-Package-Version"))
	}
	if input.NewVersion == "" {
		input.NewVersion = strings.TrimSpace(r.Header.Get("X-New-Version"))
	}
	if input.RepairOf == "" {
		input.RepairOf = strings.TrimSpace(r.Header.Get("X-Repair-Of"))
	}
	if input.Reason == "" {
		input.Reason = strings.TrimSpace(r.Header.Get("X-Repair-Reason"))
	}
	return input, nil
}

func firstValue(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.FormValue(name)); value != "" {
			return value
		}
		if value := strings.TrimSpace(r.URL.Query().Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func resolveIdentity(pathName, pathVersion string, input uploadInput) (string, string, error) {
	name := pathName
	if name == "" {
		name = input.Name
	} else if input.Name != "" && input.Name != pathName {
		return "", "", errFieldMismatch
	}
	version := pathVersion
	if version == "" {
		version = input.Version
	} else if input.Version != "" && input.Version != pathVersion {
		return "", "", errFieldMismatch
	}
	if name == "" {
		return "", "", errInvalidName
	}
	if version == "" {
		return "", "", errInvalidVersion
	}
	return name, version, nil
}
