//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bucket

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/viper"
)

type BuildBucket interface {
	GetDownloader(url string, region string) Bucket
}

type BucketBuilder struct {
}

func (bd *BucketBuilder) GetBucket(url string, region string) Bucket {
	return &s3Bucket{
		url,
		region,
	}
}

type Bucket interface {
	ListFiles(ctx context.Context, bucket string, token *string, max int32) ([]string, *string, error)
	DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error)
	GetEncoding(ctx context.Context, bucket string, item string) (string, error)
}

type s3Bucket struct {
	url    string
	region string
}

func GetDefaultBucket(url string, region string) Bucket {
	return &s3Bucket{url, region}
}

func (d *s3Bucket) getS3Client(ctx context.Context) (*s3.Client, error) {
	s3Config := &viper.Viper{}
	s3Config.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	s3Config.AutomaticEnv()

	accessKey := s3Config.GetString("storage-access-key")
	secretKey := s3Config.GetString("storage-secret-key")
	region := s3Config.GetString("storage-region")
	if region == "" {
		region = d.region
	}

	cfg, err := config.LoadDefaultConfig(ctx)

	if err != nil {
		return nil, fmt.Errorf("error loading AWS SDK config: %w", err)
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		if d.url != "" {
			o.BaseEndpoint = aws.String(d.url)
		}

		if region != "" {
			o.Region = region
		}

		if accessKey != "" && secretKey != "" {
			staticProvider := credentials.NewStaticCredentialsProvider(
				accessKey,
				secretKey,
				"",
			)
			o.Credentials = staticProvider
		}

	}), nil

}

func (d *s3Bucket) ListFiles(ctx context.Context, bucket string, token *string, max int32) ([]string, *string, error) {
	client, err := d.getS3Client(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating S3 client: %w", err)
	}

	input := &s3.ListObjectsV2Input{
		Bucket:            &bucket,
		ContinuationToken: token,
		MaxKeys:           aws.Int32(max),
	}
	resp, err := client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("error listing files: %w", err)
	}

	var files []string
	for _, item := range resp.Contents {
		files = append(files, *item.Key)
	}
	return files, resp.NextContinuationToken, nil
}

func (d *s3Bucket) DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error) {
	client, err := d.getS3Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating S3 client: %w", err)
	}

	// Create a GetObjectInput with the bucket name and object key.
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(item),
	}

	resp, err := client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("unable to download file: %w", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	n, err := io.Copy(buf, resp.Body)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("unable to read file contents: %w", err)
	}

	return buf.Bytes(), nil
}

func (d *s3Bucket) GetEncoding(ctx context.Context, bucket string, item string) (string, error) {
	logger := logging.FromContext(ctx)
	client, err := d.getS3Client(ctx)
	if err != nil {
		return "", fmt.Errorf("error creating S3 client: %w", err)
	}

	logger.Infof("Downloading document %v from bucket %v", item, bucket)

	headObject, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(item)})
	if err != nil {
		return "", fmt.Errorf("could not get head object: %w", err)
	}

	if headObject.ContentEncoding == nil {
		return "", nil
	}

	return *headObject.ContentEncoding, nil
}
