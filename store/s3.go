package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// S3 is the production Store: versioned snapshot/bootstrap JSON objects in an
// S3-API bucket (the platform object-storage standard). minio-go is used as
// the S3 client.
type S3 struct {
	client *minio.Client
	bucket string
	prefix string
	ver    *versions
}

// S3Options configures the S3 store.
type S3Options struct {
	Endpoint  string // host[:port], no scheme
	AccessKey string
	SecretKey string
	UseSSL    bool
	Bucket    string
	Prefix    string // optional key prefix, e.g. "trust-anchor/"
}

// NewS3 connects the S3 store. It does not create the bucket — provisioning
// is an ops concern.
func NewS3(opts S3Options) (*S3, error) {
	client, err := minio.New(opts.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(opts.AccessKey, opts.SecretKey, ""),
		Secure: opts.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("store: s3 client: %w", err)
	}
	prefix := opts.Prefix
	if prefix != "" && prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}
	s := &S3{client: client, bucket: opts.Bucket, prefix: prefix}
	s.ver = newVersions(s)

	return s, nil
}

func (s *S3) put(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, s.bucket, s.prefix+key, bytes.NewReader(b), int64(len(b)), minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return fmt.Errorf("store: s3 put %s: %w", key, err)
	}
	return nil
}

func (s *S3) get(ctx context.Context, key string, v any) (bool, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, s.prefix+key, minio.GetObjectOptions{})
	if err != nil {
		return false, fmt.Errorf("store: s3 get %s: %w", key, err)
	}
	defer func() { _ = obj.Close() }()

	b, err := io.ReadAll(obj)
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("store: s3 read %s: %w", key, err)
	}
	return true, json.Unmarshal(b, v)
}

func (s *S3) list(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: s.prefix + prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("store: s3 list %s: %w", prefix, obj.Err)
		}
		keys = append(keys, strings.TrimPrefix(obj.Key, s.prefix))
	}

	return keys, nil
}

func (s *S3) remove(ctx context.Context, key string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, s.prefix+key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("store: s3 remove %s: %w", key, err)
	}

	return nil
}

// SaveSnapshot writes the version object (its key is stable for the version, so
// a same-id save overwrites it) and then the latest pointer.
func (s *S3) SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error {
	return s.ver.save(ctx, snap)
}

// SweepSnapshots removes the version objects a newer version replaced before
// the given time.
func (s *S3) SweepSnapshots(ctx context.Context, before time.Time) (int, error) {
	return s.ver.sweep(ctx, before)
}

func (s *S3) LoadLatestSnapshot(ctx context.Context) (*trust.Snapshot, error) {
	var snap trust.Snapshot
	ok, err := s.get(ctx, latestSnapshotKey, &snap)
	if err != nil || !ok {
		return nil, err
	}
	return &snap, nil
}

func (s *S3) SaveBootstrap(ctx context.Context, b *trust.Bootstrap) error {
	if err := s.put(ctx, bootstrapKey(b), b); err != nil {
		return err
	}
	return s.put(ctx, latestBootstrapKey, b)
}

func (s *S3) LoadLatestBootstrap(ctx context.Context) (*trust.Bootstrap, error) {
	var b trust.Bootstrap
	ok, err := s.get(ctx, latestBootstrapKey, &b)
	if err != nil || !ok {
		return nil, err
	}
	return &b, nil
}
