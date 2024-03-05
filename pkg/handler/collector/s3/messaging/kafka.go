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

package messaging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
	"github.com/spf13/viper"
)

type KafkaProvider struct {
	// Kafka-specific configuration fields
	reader *kafka.Reader
}

type KafkaMessage struct {
	EventName string `json:"EventName"`
	Key       string `json:"Key"`
}

func (m *KafkaMessage) GetEvent() (EventName, error) {
	if m.EventName == "s3:ObjectCreated:Put" {
		return PUT, nil
	}
	return "", nil
}

func (m *KafkaMessage) GetBucket() (string, error) {
	info := strings.Split(m.Key, "/")
	if len(info) < 2 {
		return "", fmt.Errorf("invalid format of key: %s", m.Key)
	}
	return info[0], nil
}

func (m *KafkaMessage) GetItem() (string, error) {
	idx := strings.Index(m.Key, "/")
	if idx > 0 {
		return m.Key[idx:], nil
	} else {
		return "", fmt.Errorf("invalid format of key: %s", m.Key)
	}
}

func NewKafkaProvider(mpConfig MessageProviderConfig) (KafkaProvider, error) {
	kafkaTopic := mpConfig.Queue

	kafkaProvider := KafkaProvider{}

	kafkaConfig := &viper.Viper{}

	prefix := os.Getenv("KAFKA_PROPERTIES_ENV_PREFIX")
	prefix = strings.TrimSuffix(prefix, "_")

	kafkaConfig.SetEnvPrefix(prefix)
	kafkaConfig.SetEnvKeyReplacer(strings.NewReplacer("-", "__"))
	kafkaConfig.AutomaticEnv()
	
	mechanism, err := SASLMechanism(*kafkaConfig)
	if err != nil {
		return KafkaProvider{}, err
	}

	tlsConfig, err := TLSConfig(*kafkaConfig)
	if err != nil {
		return KafkaProvider{}, err
	}

	dialer := &kafka.Dialer{
		Timeout:       10 * time.Second,
		DualStack:     true,
		SASLMechanism: mechanism,
		TLS: tlsConfig,
	}

	kafkaProvider.reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{mpConfig.Endpoint},
		Topic:     kafkaTopic,
		Partition: 0,
		Dialer:    dialer,
	})

	err = kafkaProvider.reader.SetOffset(kafka.LastOffset)
	if err != nil {
		return KafkaProvider{}, err
	}

	return kafkaProvider, nil
}

func SASLMechanism(kafkaConfig viper.Viper) (sasl.Mechanism, error) {
	protocol := kafkaConfig.GetString("security-protocol")
	saslProtocols := make(map[string]struct{})
	saslProtocols["SASL_PLAINTEXT"] = struct{}{}
	saslProtocols["SASL_SSL"] = struct{}{}

	_, isSasl := saslProtocols[protocol]
	if !isSasl{
		return nil, nil
	}
	mechanism := kafkaConfig.GetString("sasl-mechanism")
	username := kafkaConfig.GetString("sasl-username")
	password := kafkaConfig.GetString("sasl-password")

	switch mechanism {
	case "SCRAM-SHA-256":
		return scram.Mechanism(scram.SHA256, username, password)
	case "SCRAM-SHA-512":
		return scram.Mechanism(scram.SHA512, username, password)
	case "PLAIN":
		return plain.Mechanism{
			Username: username,
			Password: password,
		}, nil
	default:
		return nil, nil
	}
}

func TLSConfig(kafkaConfig viper.Viper) (*tls.Config, error) {
	protocol := kafkaConfig.GetString("security-protocol")
	tlsProtocols := make(map[string]struct{})
	tlsProtocols["SSL"] = struct{}{}
	tlsProtocols["SASL_SSL"] = struct{}{}

	_, isTls := tlsProtocols[protocol]
	if !isTls{
		return nil, nil
	}
	sslCaLocation := kafkaConfig.GetString("ssl.ca.location")
	verifyClientCert := kafkaConfig.GetBool("enable.ssl.certificate.verification")

	caFile, err := os.ReadFile(sslCaLocation)
	if err != nil {
		return nil, nil
	}
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	rootCAs.AppendCertsFromPEM(caFile)

	return &tls.Config{
		InsecureSkipVerify: !verifyClientCert,
		RootCAs:       rootCAs,
	}, nil

}

func (k *KafkaProvider) ReceiveMessage(ctx context.Context) (Message, error) {
	logger := logging.FromContext(ctx)

	m, err := k.reader.ReadMessage(ctx)
	if err != nil {
		fmt.Println(err.Error())
	}
	logger.Debugf("Message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))

	msg := KafkaMessage{}
	err = json.Unmarshal(m.Value, &msg)
	if err != nil {
		return &msg, fmt.Errorf("error parsing JSON: %w", err)
	}

	return &msg, err
}

func (k *KafkaProvider) Close(ctx context.Context) error {
	logger := logging.FromContext(ctx)

	if err := k.reader.Close(); err != nil {
		logger.Errorf("failed to close reader: %v", err)
		return err
	}

	return nil
}
