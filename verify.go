package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Verification struct {
	Valid          bool   `json:"valid"`
	SignatureValid bool   `json:"signature_valid"`
	DigestValid    bool   `json:"digest_valid"`
	KeyID          string `json:"key_id,omitempty"`
	ExpectedDigest string `json:"expected_digest"`
	ActualDigest   string `json:"actual_digest,omitempty"`
	Detail         string `json:"detail"`
}

func (s *Store) Verify(release Release) Verification {
	result := Verification{
		SignatureValid: s.key.verify(release),
		ExpectedDigest: release.ContentDigest,
		KeyID:          release.Signature.KeyID,
	}
	digestHex, ok := digestHex(release.ContentDigest)
	if !ok {
		result.Detail = "内容摘要格式无效，无法验证归档。"
		return result
	}

	f, err := os.Open(filepath.Join(s.objectDir, digestHex+".tar"))
	if err != nil {
		result.Detail = "归档对象缺失，无法完成验证。"
		return result
	}
	defer f.Close()

	actualHex, actualSize, err := hashOpenFile(f)
	if err != nil {
		result.Detail = "读取归档对象失败，无法完成验证。"
		return result
	}
	result.ActualDigest = "sha256:" + actualHex
	result.DigestValid = actualHex == digestHex && actualSize == release.Archive.Size
	result.Valid = result.SignatureValid && result.DigestValid
	switch {
	case result.Valid:
		result.Detail = "发布签名有效，内容摘要与归档一致。"
	case !result.SignatureValid && !result.DigestValid:
		result.Detail = "发布签名和内容摘要均验证失败。"
	case !result.SignatureValid:
		result.Detail = "发布签名验证失败，元数据可能被改写。"
	default:
		result.Detail = "内容摘要验证失败，归档可能被篡改。"
	}
	return result
}

func (s *Store) OpenVerified(release Release) (*os.File, Verification, error) {
	digestHex, ok := digestHex(release.ContentDigest)
	if !ok {
		return nil, Verification{Detail: "内容摘要格式无效。"}, fmt.Errorf("invalid content digest")
	}
	f, err := os.Open(filepath.Join(s.objectDir, digestHex+".tar"))
	if err != nil {
		return nil, Verification{Detail: "归档对象缺失。"}, err
	}

	result := Verification{
		SignatureValid: s.key.verify(release),
		ExpectedDigest: release.ContentDigest,
		KeyID:          release.Signature.KeyID,
	}
	actualHex, actualSize, err := hashOpenFile(f)
	if err != nil {
		_ = f.Close()
		return nil, result, err
	}
	result.ActualDigest = "sha256:" + actualHex
	result.DigestValid = actualHex == digestHex && actualSize == release.Archive.Size
	result.Valid = result.SignatureValid && result.DigestValid
	if !result.Valid {
		_ = f.Close()
		result.Detail = "签名或内容摘要验证失败，下载已拒绝。"
		return nil, result, fmt.Errorf("release verification failed")
	}
	result.Detail = "发布签名有效，内容摘要与归档一致。"
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, result, err
	}
	return f, result, nil
}

func hashOpenFile(f *os.File) (string, int64, error) {
	hasher := sha256.New()
	size, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}
